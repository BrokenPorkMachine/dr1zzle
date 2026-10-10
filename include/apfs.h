#ifndef DR1ZZLE_APFS_H
#define DR1ZZLE_APFS_H

#include <stddef.h>
#include <stdint.h>

#define APFS_BLOCK_MIN 4096u
#define APFS_BLOCK_MAX 65536u
#define APFS_MAX_VOLUMES 100u

typedef int (*apfs_read_block_fn)(void *context, uint64_t block,
                                  uint8_t *out, uint32_t length);

typedef struct {
    apfs_read_block_fn read_block;
    void *context;
} apfs_io_t;

typedef struct {
    uint64_t nx_block;
    uint32_t block_size;
    uint64_t block_count;
    uint64_t incompatible_features;
    uint64_t xp_desc_base;
    uint32_t xp_desc_blocks;
    uint32_t max_file_systems;
    uint64_t fs_oid[APFS_MAX_VOLUMES];
    uint8_t uuid[16];
    int checksum_valid;
} apfs_container_info_t;

typedef struct {
    uint64_t block;
    uint32_t fs_index;
    uint64_t root_tree_oid;
    uint64_t omap_oid;
    uint8_t uuid[16];
    char name[256];
    int checksum_valid;
} apfs_volume_info_t;

typedef struct {
    uint64_t object_id;
    uint64_t logical_size;
    uint64_t physical_block;
    uint64_t physical_block_count;
    uint32_t crypto_id;
} apfs_extent_t;

typedef struct {
    const uint8_t *key;
    uint16_t key_len;
    const uint8_t *value;
    uint16_t value_len;
    uint16_t level;
} apfs_btree_entry_t;

typedef int (*apfs_btree_entry_fn)(const apfs_btree_entry_t *entry,
                                   void *context);
typedef int (*apfs_file_sink_fn)(uint64_t offset, const uint8_t *data,
                                 uint32_t length, void *context);

/* Parse one container or volume superblock. These functions do not trust a
 * length field until it has been checked against `block_len`. */
int apfs_parse_container_superblock(const uint8_t *block, uint32_t block_len,
                                    uint64_t block_number,
                                    apfs_container_info_t *out);
int apfs_parse_volume_superblock(const uint8_t *block, uint32_t block_len,
                                 uint64_t block_number,
                                 apfs_volume_info_t *out);
int apfs_verify_checksum(const uint8_t *block, uint32_t block_len);

/* Locate the latest-looking NXSB and one volume superblock without assuming
 * that an image has a usable checkpoint map. `scan_blocks` is a hard cap. */
int apfs_open(const apfs_io_t *io, uint32_t scan_blocks,
              apfs_container_info_t *container, apfs_volume_info_t *volume);
int apfs_find_volume(const apfs_io_t *io, const apfs_container_info_t *container,
                     uint32_t index, uint32_t scan_blocks,
                     apfs_volume_info_t *volume);

/* Walk a B-tree node using the APFS variable-key/value table. Internal-node
 * values are treated as child block numbers; an OMAP resolver can be layered
 * on top by supplying a reader that translates those numbers. */
int apfs_btree_walk(const apfs_io_t *io, uint64_t root_block,
                    uint32_t block_size, apfs_btree_entry_fn callback,
                    void *context);

/* Decode an APFS file-extent value and stream its physical blocks. */
int apfs_decode_extent(uint64_t object_id, const uint8_t *value,
                       uint16_t value_len, apfs_extent_t *out);
int apfs_read_extent(const apfs_io_t *io, const apfs_extent_t *extent,
                     uint32_t block_size, apfs_file_sink_fn sink,
                     void *context);

#endif /* DR1ZZLE_APFS_H */
