/*
 * VFS Core Implementation
 * Provides virtual file system layer for on-demand asset loading
 */

#include "vfs.h"
#include "string.h"
#include "util.h"
#include "uart.h"
#include "stdlib.h"

/* ========================================================================
 * Global State
 * ======================================================================== */

static struct vfs_context g_vfs = {0};
static const vfs_fs_ops_t *g_fs_types[8] = {0};
static uint32_t g_fs_type_count = 0;

vfs_module_t g_modules[16] = {0};
uint32_t g_module_count = 0;

vfs_asset_t g_assets[32] = {0};
uint32_t g_asset_count = 0;
size_t g_asset_cache_size = 0;

/* ========================================================================
 * Filesystem Type Registration
 * ======================================================================== */

int vfs_register_fs(const vfs_fs_ops_t *ops) {
    if (!ops || !ops->name) return -1;
    
    for (uint32_t i = 0; i < g_fs_type_count; i++) {
        if (g_fs_types[i] && strcmp(g_fs_types[i]->name, ops->name) == 0) {
            uart_puts("vfs: fs type '"); uart_puts(ops->name); uart_puts("' already registered\n");
            return -1;
        }
    }
    
    for (uint32_t i = 0; i < 8; i++) {
        if (!g_fs_types[i]) {
            g_fs_types[i] = ops;
            g_fs_type_count++;
            uart_puts("vfs: registered fs type '"); uart_puts(ops->name); uart_puts("'\n");
            return 0;
        }
    }
    return -1;
}

int vfs_unregister_fs(const char *name) {
    for (uint32_t i = 0; i < g_fs_type_count; i++) {
        if (g_fs_types[i] && strcmp(g_fs_types[i]->name, name) == 0) {
            g_fs_types[i] = NULL;
            g_fs_type_count--;
            return 0;
        }
    }
    return -1;
}

static const vfs_fs_ops_t *vfs_find_fstype(const char *name) {
    for (uint32_t i = 0; i < g_fs_type_count; i++) {
        if (g_fs_types[i] && strcmp(g_fs_types[i]->name, name) == 0) {
            return g_fs_types[i];
        }
    }
    return NULL;
}

/* ========================================================================
 * Path Resolution
 * ======================================================================== */

int vfs_resolve_path(const char *path, char *resolved, size_t resolved_size) {
    if (!path || !resolved || resolved_size == 0) return -1;
    
    const char *src = path;
    char *dst = resolved;
    size_t remaining = resolved_size - 1;
    
    if (path[0] != '/') {
        size_t cwd_len = strlen(g_vfs.cwd);
        if (cwd_len + 1 >= resolved_size) return -1;
        strcpy(dst, g_vfs.cwd);
        dst += cwd_len;
        *dst++ = '/';
        remaining -= cwd_len + 1;
    } else {
        *dst++ = '/';
        remaining--;
        src++;
    }
    
    while (*src && remaining > 0) {
        if (*src == '.') {
            if (src[1] == '/' || src[1] == '\0') {
                src++;
                if (*src == '/') src++;
                continue;
            }
            if (src[1] == '.' && (src[2] == '/' || src[2] == '\0')) {
                src += 2;
                if (*src == '/') src++;
                
                char *last_slash = resolved;
                for (char *p = resolved; p < dst; p++) {
                    if (*p == '/') last_slash = p;
                }
                if (last_slash > resolved) {
                    dst = last_slash;
                    remaining = resolved_size - (dst - resolved);
                } else {
                    dst = resolved + 1;
                    remaining = resolved_size - 1;
                }
                continue;
            }
        }
        
        while (*src && *src != '/' && remaining > 0) {
            *dst++ = *src++;
            remaining--;
        }
        if (*src == '/') {
            *dst++ = '/';
            remaining--;
            src++;
        }
    }
    
    if (dst > resolved + 1 && dst[-1] == '/') {
        dst--;
    }
    *dst = '\0';
    return 0;
}

/* ========================================================================
 * Mount/Unmount
 * ======================================================================== */

int vfs_mount(const char *source, const char *target, const char *fstype, uint32_t flags, void *data) {
    const vfs_fs_ops_t *ops = vfs_find_fstype(fstype);
    if (!ops) {
        uart_puts("vfs: unknown fs type '"); uart_puts(fstype); uart_puts("'\n");
        return -1;
    }
    
    char resolved[VFS_MAX_PATH];
    if (vfs_resolve_path(target, resolved, sizeof(resolved)) != 0) {
        return -1;
    }
    
    struct vfs_fs *fs = malloc(sizeof(struct vfs_fs));
    if (!fs) return -1;
    memset(fs, 0, sizeof(struct vfs_fs));
    
    fs->ops = ops;
    fs->flags = flags;
    strncpy(fs->mount_point, resolved, sizeof(fs->mount_point) - 1);
    fs->refcount = 1;
    
    int ret = ops->mount(fs, source, flags, data);
    if (ret != 0) {
        free(fs);
        return ret;
    }
    
    for (uint32_t i = 0; i < 16; i++) {
        if (!g_vfs.mounted_fs[i]) {
            g_vfs.mounted_fs[i] = fs;
            g_vfs.mounted_count++;
            break;
        }
    }
    
    if (!g_vfs.root_fs) {
        g_vfs.root_fs = fs;
    }
    
    uart_puts("vfs: mounted "); uart_puts(fstype); uart_puts(" on "); uart_puts(resolved); uart_puts("\n");
    return 0;
}

int vfs_unmount(const char *target) {
    char resolved[VFS_MAX_PATH];
    if (vfs_resolve_path(target, resolved, sizeof(resolved)) != 0) {
        return -1;
    }
    
    for (uint32_t i = 0; i < 16; i++) {
        struct vfs_fs *fs = g_vfs.mounted_fs[i];
        if (fs && strcmp(fs->mount_point, resolved) == 0) {
            int ret = fs->ops->unmount(fs);
            if (ret == 0) {
                g_vfs.mounted_fs[i] = NULL;
                g_vfs.mounted_count--;
                if (g_vfs.root_fs == fs) g_vfs.root_fs = NULL;
                free(fs);
                uart_puts("vfs: unmounted "); uart_puts(resolved); uart_puts("\n");
                return 0;
            }
            return ret;
        }
    }
    return -1;
}

/* ========================================================================
 * File Operations
 * ======================================================================== */

int vfs_open(const char *path, int flags, struct vfs_file **file_out) {
    char resolved[VFS_MAX_PATH];
    if (vfs_resolve_path(path, resolved, sizeof(resolved)) != 0) {
        return -1;
    }
    
    struct vfs_fs *fs = NULL;
    for (uint32_t i = 0; i < 16; i++) {
        struct vfs_fs *fs = g_vfs.mounted_fs[i];
        if (fs && strncmp(resolved, fs->mount_point, strlen(fs->mount_point)) == 0) {
            break;
        }
    }
    
    if (!fs) {
        fs = g_vfs.root_fs;
    }
    if (!fs) return -1;
    
    struct vfs_file *file = malloc(sizeof(struct vfs_file));
    if (!file) return -1;
    memset(file, 0, sizeof(struct vfs_file));
    
    file->fs = fs;
    file->flags = flags;
    file->pos = 0;
    file->refcount = 1;
    
    int ret = fs->ops->open(fs, file, resolved, flags);
    if (ret != 0) {
        free(file);
        return ret;
    }
    
    fs->refcount++;
    *file_out = file;
    return 0;
}

int vfs_close(struct vfs_file *file) {
    if (!file) return -1;
    
    int ret = file->fs->ops->close(file);
    file->fs->refcount--;
    free(file);
    return ret;
}

ssize_t vfs_read(struct vfs_file *file, void *buf, size_t count) {
    if (!file || !buf) return -1;
    return file->fs->ops->read(file, buf, count);
}

ssize_t vfs_write(struct vfs_file *file, const void *buf, size_t count) {
    if (!file || !buf) return -1;
    return file->fs->ops->write(file, buf, count);
}

off_t vfs_lseek(struct vfs_file *file, off_t offset, int whence) {
    if (!file) return -1;
    return file->fs->ops->lseek(file, offset, whence);
}

/* ========================================================================
 * Directory Operations
 * ======================================================================== */

int vfs_opendir(const char *path, struct vfs_dir **dir_out) {
    char resolved[VFS_MAX_PATH];
    if (vfs_resolve_path(path, resolved, sizeof(resolved)) != 0) {
        return -1;
    }
    
    struct vfs_fs *fs = g_vfs.root_fs;
    if (!fs) return -1;
    
    struct vfs_dir *dir = malloc(sizeof(struct vfs_dir));
    if (!dir) return -1;
    memset(dir, 0, sizeof(struct vfs_dir));
    
    dir->fs = fs;
    int ret = fs->ops->opendir(fs, dir, resolved);
    if (ret != 0) {
        free(dir);
        return ret;
    }
    
    *dir_out = dir;
    return 0;
}

int vfs_readdir(struct vfs_dir *dir, struct vfs_dirent *ent) {
    if (!dir || !ent) return -1;
    return dir->fs->ops->readdir(dir, ent);
}

int vfs_closedir(struct vfs_dir *dir) {
    if (!dir) return -1;
    int ret = dir->fs->ops->closedir(dir);
    free(dir);
    return ret;
}

/* ========================================================================
 * Filesystem Info
 * ======================================================================== */

int vfs_statfs(const char *path, struct vfs_statfs *buf) {
    char resolved[VFS_MAX_PATH];
    if (vfs_resolve_path(path, resolved, sizeof(resolved)) != 0) {
        return -1;
    }
    
    struct vfs_fs *fs = g_vfs.root_fs;
    if (!fs || !fs->ops->statfs) return -1;
    
    return fs->ops->statfs(fs, buf);
}

/* ========================================================================
 * Module Loading
 * ======================================================================== */

int vfs_load_module(const char *path, void **entry_out, void **handle_out) {
    char resolved[VFS_MAX_PATH];
    if (vfs_resolve_path(path, resolved, sizeof(resolved)) != 0) {
        return -1;
    }
    
    struct vfs_fs *fs = g_vfs.root_fs;
    if (!fs || !fs->ops->load_module) return -1;
    
    void *entry = NULL;
    void *handle = malloc(sizeof(void*));
    int ret = fs->ops->load_module(fs, resolved, &entry);
    if (ret != 0) {
        free(handle);
        return ret;
    }
    
    vfs_module_t *mod = NULL;
    for (uint32_t i = 0; i < 16; i++) {
        if (!g_modules[i].handle) {
            mod = &g_modules[i];
            break;
        }
    }
    
    if (!mod) {
        free(handle);
        return -1;
    }
    
    strncpy(mod->name, resolved, sizeof(mod->name) - 1);
    mod->handle = handle;
    mod->entry = entry;
    mod->refcount = 1;
    g_module_count++;
    
    if (entry_out) *entry_out = entry;
    if (handle_out) *handle_out = handle;
    
    uart_puts("vfs: loaded module "); uart_puts(resolved); uart_puts("\n");
    return 0;
}

int vfs_unload_module(void *handle) {
    for (uint32_t i = 0; i < 16; i++) {
        if (g_modules[i].handle == handle) {
            g_modules[i].handle = NULL;
            g_modules[i].entry = NULL;
            free(handle);
            g_module_count--;
            return 0;
        }
    }
    return -1;
}

/* ========================================================================
 * Module Registry
 * ======================================================================== */

int vfs_module_register(const char *name, void *handle, void *entry) {
    for (uint32_t i = 0; i < 16; i++) {
        if (!g_modules[i].handle) {
            strncpy(g_modules[i].name, name, sizeof(g_modules[i].name) - 1);
            g_modules[i].handle = handle;
            g_modules[i].entry = entry;
            g_modules[i].refcount = 1;
            g_module_count++;
            return 0;
        }
    }
    return -1;
}

int vfs_module_unregister(const char *name) {
    for (uint32_t i = 0; i < 16; i++) {
        if (g_modules[i].handle && strcmp(g_modules[i].name, name) == 0) {
            g_modules[i].handle = NULL;
            g_modules[i].entry = NULL;
            g_module_count--;
            return 0;
        }
    }
    return -1;
}

vfs_module_t *vfs_module_find(const char *name) {
    for (uint32_t i = 0; i < 16; i++) {
        if (g_modules[i].handle && strcmp(g_modules[i].name, name) == 0) {
            return &g_modules[i];
        }
    }
    return NULL;
}

/* ========================================================================
 * Asset Loading (Second-tier assets)
 * ======================================================================== */

vfs_asset_t *vfs_asset_load(const char *path, uint32_t flags) {
    char resolved[VFS_MAX_PATH];
    if (vfs_resolve_path(path, resolved, sizeof(resolved)) != 0) {
        return NULL;
    }
    
    for (uint32_t i = 0; i < g_asset_count; i++) {
        if (g_assets[i].data && strcmp(g_assets[i].path, resolved) == 0) {
            g_assets[i].refcount++;
            return &g_assets[i];
        }
    }
    
    vfs_asset_t *asset = NULL;
    for (uint32_t i = 0; i < 32; i++) {
        if (!g_assets[i].data) {
            asset = &g_assets[i];
            break;
        }
    }
    if (!asset) return NULL;
    
    struct vfs_file *file;
    if (vfs_open(resolved, VFS_O_RDONLY, &file) != 0) {
        return NULL;
    }
    
    off_t size = vfs_lseek(file, 0, VFS_SEEK_END);
    if (size <= 0) {
        vfs_close(file);
        return NULL;
    }
    vfs_lseek(file, 0, VFS_SEEK_SET);
    
    void *data = malloc(size);
    if (!data) {
        vfs_close(file);
        return NULL;
    }
    
    ssize_t read = vfs_read(file, data, size);
    vfs_close(file);
    
    if (read != size) {
        free(data);
        return NULL;
    }
    
    asset->path = strdup(resolved);
    asset->data = data;
    asset->size = size;
    asset->flags = flags;
    asset->refcount = 1;
    g_asset_cache_size += size;
    g_asset_count++;
    
    uart_puts("vfs: loaded asset "); uart_puts(resolved); uart_puts(" (");
    uart_puts(utoa(size)); uart_puts(" bytes)\n");
    
    return asset;
}

void vfs_asset_unload(vfs_asset_t *asset) {
    if (!asset) return;
    
    asset->refcount--;
    if (asset->refcount == 0) {
        if (asset->data) {
            g_asset_cache_size -= asset->size;
            free(asset->data);
            asset->data = NULL;
        }
        if (asset->path) {
            free((void*)asset->path);
            asset->path = NULL;
        }
        asset->size = 0;
        asset->flags = 0;
        g_asset_count--;
    }
}

void vfs_asset_cache_prune(size_t max_cache_size) {
    if (g_asset_cache_size <= max_cache_size) return;
    
    for (uint32_t i = 0; i < 32 && g_asset_cache_size > max_cache_size; i++) {
        if (g_assets[i].data && g_assets[i].refcount == 0) {
            vfs_asset_unload(&g_assets[i]);
        }
    }
}

/* ========================================================================
 * VFS Initialization
 * ======================================================================== */

void vfs_init(void) {
    memset(&g_vfs, 0, sizeof(g_vfs));
    memset(g_fs_types, 0, sizeof(g_fs_types));
    memset(g_modules, 0, sizeof(g_modules));
    memset(g_assets, 0, sizeof(g_assets));
    strcpy(g_vfs.cwd, "/");
    uart_puts("vfs: initialized\n");
}
