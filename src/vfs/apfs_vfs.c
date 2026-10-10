/*
 * APFS Filesystem Driver for VFS
 * Implements VFS operations using the existing APFS reader
 */

#include "vfs.h"
#include "apfs.h"
#include "string.h"
#include "util.h"
#include "uart.h"
#include "nand.h"
#include "memory_map.h"
#include "stdlib.h"

/* ========================================================================
 * APFS File Handle
 * ======================================================================== */

typedef struct {
    void *file_data;  /* Opaque APFS file handle */
    uint64_t pos;
    uint32_t flags;
} apfs_vfs_file_t;

typedef struct {
    void *dir_data;  /* Opaque APFS directory handle */
    uint32_t index;
} apfs_vfs_dir_t;

/* ========================================================================
 * APFS Filesystem Instance
 * ======================================================================== */

typedef struct {
    apfs_io_t io;
    apfs_container_info_t container;
    apfs_volume_info_t volume;
    bool mounted;
} apfs_vfs_fs_t;

/* ========================================================================
 * NAND Read Callback
 * ======================================================================== */

static int apfs_nand_read(void *context, uint64_t block, uint8_t *out, uint32_t length) {
    (void)context;
    const nand_info_t *info = nand_info();
    if (!out || length != info->geometry.page_size ||
        block >= (uint64_t)info->geometry.block_count * info->geometry.pages_per_block) {
        return -1;
    }
    uint32_t nand_block = (uint32_t)(block / info->geometry.pages_per_block);
    uint32_t page = (uint32_t)(block % info->geometry.pages_per_block);
    return nand_read_page(nand_block, page, out, 0);
}

/* ========================================================================
 * VFS Operations
 * ======================================================================== */

static int apfs_vfs_mount(struct vfs_fs *fs, const char *source, uint32_t flags, void *data) {
    (void)source; (void)flags; (void)data;
    
    apfs_vfs_fs_t *afs = malloc(sizeof(apfs_vfs_fs_t));
    if (!afs) return -1;
    memset(afs, 0, sizeof(apfs_vfs_fs_t));
    
    afs->io.read_block = apfs_nand_read;
    afs->io.context = NULL;
    
    int rc = apfs_open(&afs->io, 4096, &afs->container, &afs->volume);
    if (rc < 0) {
        free(afs);
        return -1;
    }
    
    afs->mounted = true;
    fs->private_data = afs;
    
    uart_puts("apfs: mounted volume "); uart_puts(afs->volume.name); uart_puts("\n");
    return 0;
}

static int apfs_vfs_unmount(struct vfs_fs *fs) {
    apfs_vfs_fs_t *afs = fs->private_data;
    if (afs) {
        afs->mounted = false;
        free(afs);
    }
    fs->private_data = NULL;
    return 0;
}

/* ========================================================================
 * File Operations
 * ======================================================================== */

static int apfs_vfs_open(struct vfs_fs *fs, struct vfs_file *file, const char *path, int flags) {
    (void)path;
    apfs_vfs_fs_t *afs = fs->private_data;
    if (!afs || !afs->mounted) return -1;
    
    apfs_vfs_file_t *afile = malloc(sizeof(apfs_vfs_file_t));
    if (!afile) return -1;
    memset(afile, 0, sizeof(apfs_vfs_file_t));
    
    afile->pos = 0;
    afile->flags = flags;
    file->private_data = afile;
    
    return 0;
}

static int apfs_vfs_close(struct vfs_file *file) {
    if (file->private_data) {
        free(file->private_data);
        file->private_data = NULL;
    }
    return 0;
}

static ssize_t apfs_vfs_read(struct vfs_file *file, void *buf, size_t count) {
    (void)buf; (void)count;
    apfs_vfs_file_t *afile = file->private_data;
    if (!afile) return -1;
    
    /* For now, return 0 (EOF) - actual implementation would read from APFS extent */
    return 0;
}

static ssize_t apfs_vfs_write(struct vfs_file *file, const void *buf, size_t count) {
    (void)file; (void)buf; (void)count;
    return -1; /* Read-only for now */
}

static off_t apfs_vfs_lseek(struct vfs_file *file, off_t offset, int whence) {
    apfs_vfs_file_t *afile = file->private_data;
    if (!afile) return -1;
    
    switch (whence) {
        case VFS_SEEK_SET:
            if (offset < 0) return -1;
            afile->pos = offset;
            break;
        case VFS_SEEK_CUR:
            if (afile->pos + offset < 0) return -1;
            afile->pos += offset;
            break;
        case VFS_SEEK_END:
            return -1; /* Not implemented */
        default:
            return -1;
    }
    return afile->pos;
}

/* ========================================================================
 * Directory Operations
 * ======================================================================== */

static int apfs_vfs_opendir(struct vfs_fs *fs, struct vfs_dir *dir, const char *path) {
    (void)path;
    apfs_vfs_fs_t *afs = fs->private_data;
    if (!afs || !afs->mounted) return -1;
    
    apfs_vfs_dir_t *adir = malloc(sizeof(apfs_vfs_dir_t));
    if (!adir) return -1;
    memset(adir, 0, sizeof(apfs_vfs_dir_t));
    adir->index = 0;
    dir->private_data = adir;
    return 0;
}

static int apfs_vfs_readdir(struct vfs_dir *dir, struct vfs_dirent *ent) {
    (void)ent;
    apfs_vfs_dir_t *adir = dir->private_data;
    if (!adir) return -1;
    
    /* For now, return no entries */
    return 0;
}

static int apfs_vfs_closedir(struct vfs_dir *dir) {
    if (dir->private_data) {
        free(dir->private_data);
        dir->private_data = NULL;
    }
    return 0;
}

/* ========================================================================
 * Module Loading
 * ======================================================================== */

static int apfs_vfs_load_module(struct vfs_fs *fs, const char *path, void **entry_out) {
    (void)fs; (void)path; (void)entry_out;
    /* Module loading from APFS would require finding the file and loading it */
    return -1; /* Not implemented yet */
}

static int apfs_vfs_statfs(struct vfs_fs *fs, struct vfs_statfs *buf) {
    (void)fs;
    if (!buf) return -1;
    buf->f_blocks = 0;
    buf->f_bfree = 0;
    buf->f_bavail = 0;
    buf->f_bsize = 4096;
    buf->f_namelen = 255;
    return 0;
}

/* ========================================================================
 * APFS VFS Operations Structure
 * ======================================================================== */

static const vfs_fs_ops_t apfs_vfs_ops = {
    .name = "apfs",
    .mount = apfs_vfs_mount,
    .unmount = apfs_vfs_unmount,
    .open = apfs_vfs_open,
    .close = apfs_vfs_close,
    .read = apfs_vfs_read,
    .write = apfs_vfs_write,
    .lseek = apfs_vfs_lseek,
    .opendir = apfs_vfs_opendir,
    .readdir = apfs_vfs_readdir,
    .closedir = apfs_vfs_closedir,
    .load_module = apfs_vfs_load_module,
    .statfs = apfs_vfs_statfs,
};

/* ========================================================================
 * Registration
 * ======================================================================== */

int apfs_vfs_register(void) {
    return vfs_register_fs(&apfs_vfs_ops);
}