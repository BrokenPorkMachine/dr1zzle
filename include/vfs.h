#ifndef VFS_H
#define VFS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* off_t and ssize_t types for file operations */
typedef int64_t off_t;
typedef int64_t ssize_t;

/* Virtual File System layer for on-demand asset loading */

/* File types */
#define VFS_TYPE_REGULAR  1
#define VFS_TYPE_DIR      2
#define VFS_TYPE_SYMLINK  3
#define VFS_TYPE_BLOCK    4
#define VFS_TYPE_CHAR     5
#define VFS_TYPE_FIFO     5
#define VFS_TYPE_SOCKET   6

/* File open flags */
#define VFS_O_RDONLY      0x0000
#define VFS_O_WRONLY      0x0001
#define VFS_O_RDWR        0x0002
#define VFS_O_CREAT       0x0040
#define VFS_O_TRUNC       0x0200
#define VFS_O_APPEND      0x0400

/* Seek whence */
#define VFS_SEEK_SET      0
#define VFS_SEEK_CUR      1
#define VFS_SEEK_END      2

/* Maximum path length */
#define VFS_MAX_PATH      256
#define VFS_MAX_NAME      64

/* Directory entry */
struct vfs_dirent {
    uint32_t d_ino;
    uint8_t  d_type;
    char     d_name[VFS_MAX_NAME];
};

/* Filesystem stat */
struct vfs_statfs {
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint32_t f_bsize;
    uint32_t f_namelen;
};

/* Forward declarations */
struct vfs_fs;
struct vfs_file;
struct vfs_dir;

/* Filesystem operations */
typedef struct vfs_fs_ops {
    const char *name;
    
    /* Mount/unmount */
    int (*mount)(struct vfs_fs *fs, const char *source, uint32_t flags, void *data);
    int (*unmount)(struct vfs_fs *fs);
    
    /* File operations */
    int (*open)(struct vfs_fs *fs, struct vfs_file *file, const char *path, int flags);
    int (*close)(struct vfs_file *file);
    ssize_t (*read)(struct vfs_file *file, void *buf, size_t count);
    ssize_t (*write)(struct vfs_file *file, const void *buf, size_t count);
    off_t (*lseek)(struct vfs_file *file, off_t offset, int whence);
    
    /* Directory operations */
    int (*opendir)(struct vfs_fs *fs, struct vfs_dir *dir, const char *path);
    int (*readdir)(struct vfs_dir *dir, struct vfs_dirent *ent);
    int (*closedir)(struct vfs_dir *dir);
    
    /* Filesystem info */
    int (*statfs)(struct vfs_fs *fs, struct vfs_statfs *buf);
    
    /* Module support */
    int (*load_module)(struct vfs_fs *fs, const char *path, void **entry_out);
} vfs_fs_ops_t;

/* File handle */
struct vfs_file {
    struct vfs_fs *fs;
    void *private_data;
    off_t pos;
    uint32_t flags;
    uint32_t refcount;
};

/* Directory handle */
struct vfs_dir {
    struct vfs_fs *fs;
    void *private_data;
};

/* Filesystem instance */
struct vfs_fs {
    const vfs_fs_ops_t *ops;
    void *private_data;
    char mount_point[VFS_MAX_PATH];
    uint32_t flags;
    uint32_t refcount;
};

/* VFS context */
struct vfs_context {
    struct vfs_fs *root_fs;
    struct vfs_fs *mounted_fs[16];
    uint32_t mounted_count;
    char cwd[VFS_MAX_PATH];
};

/* VFS API */
void vfs_init(void);
int vfs_register_fs(const vfs_fs_ops_t *ops);
int vfs_unregister_fs(const char *name);

int vfs_mount(const char *source, const char *target, const char *fstype, uint32_t flags, void *data);
int vfs_unmount(const char *target);

int vfs_open(const char *path, int flags, struct vfs_file **file_out);
int vfs_close(struct vfs_file *file);
ssize_t vfs_read(struct vfs_file *file, void *buf, size_t count);
ssize_t vfs_write(struct vfs_file *file, const void *buf, size_t count);
off_t vfs_lseek(struct vfs_file *file, off_t offset, int whence);

int vfs_opendir(const char *path, struct vfs_dir **dir_out);
int vfs_readdir(struct vfs_dir *dir, struct vfs_dirent *ent);
int vfs_closedir(struct vfs_dir *dir);

int vfs_statfs(const char *path, struct vfs_statfs *buf);

/* Module loading - loads executable from VFS into memory */
int vfs_load_module(const char *path, void **entry_out, void **handle_out);
int vfs_unload_module(void *handle);

/* Path resolution */
int vfs_resolve_path(const char *path, char *resolved, size_t resolved_size);

/* Module registry for loaded modules */
typedef struct {
    char name[VFS_MAX_NAME];
    void *handle;
    void *entry;
    uint32_t refcount;
} vfs_module_t;

int vfs_module_register(const char *name, void *handle, void *entry);
int vfs_module_unregister(const char *name);
vfs_module_t *vfs_module_find(const char *name);

/* Asset loading - for second-tier assets */
typedef struct {
    const char *path;
    void *data;
    size_t size;
    uint32_t flags;
    uint32_t refcount;
} vfs_asset_t;

/* Filesystem registration */
int apfs_vfs_register(void);

/* Global VFS state (for shell access) */
extern vfs_module_t g_modules[16];
extern uint32_t g_module_count;
extern vfs_asset_t g_assets[32];
extern uint32_t g_asset_count;
extern size_t g_asset_cache_size;

vfs_asset_t *vfs_asset_load(const char *path, uint32_t flags);
void vfs_asset_unload(vfs_asset_t *asset);
void vfs_asset_cache_prune(size_t max_cache_size);

#endif /* VFS_H */