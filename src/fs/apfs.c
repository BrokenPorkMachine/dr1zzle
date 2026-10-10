/* Small, read-only APFS navigator.
 *
 * This is deliberately an image reader, not a mounting implementation.  It
 * validates every on-disk offset before using it, walks the APFS variable
 * key/value table, and leaves OMAP translation to the block-reader callback.
 * NAND pages can therefore be exposed through one adapter without copying
 * APFS assumptions into the NAND controller.
 */

#include "apfs.h"

#define APFS_MAGIC_NXSB 0x4e585342u /* bytes: N X S B */
#define APFS_MAGIC_APSB 0x41505342u /* bytes: A P S B */
#define APFS_OBJECT_HEADER 32u
#define APFS_NODE_HEADER 56u
#define APFS_MAX_WALK_DEPTH 32u
#define APFS_MAX_SCAN_BLOCKS 1048576u
#define APFS_FIXED_KV_FLAG 0x0002u
#define APFS_MAX_NODE_CHILDREN 1024u

static uint8_t g_block[APFS_BLOCK_MAX];
static uint64_t g_children[APFS_MAX_WALK_DEPTH][APFS_MAX_NODE_CHILDREN];

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t le64(const uint8_t *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value |= (uint64_t)p[i] << (8u * i);
    return value;
}

static int is_power_of_two(uint32_t value) {
    return value != 0u && (value & (value - 1u)) == 0u;
}

static int has_magic(const uint8_t *p, uint32_t magic) {
    return le32(p) == magic;
}

static uint64_t fletcher64(const uint8_t *block, uint32_t length) {
    const uint64_t mod = 0xffffffffULL;
    uint64_t sum1 = 0;
    uint64_t sum2 = 0;

    for (uint32_t off = 0; off < length; off += 4u) {
        uint32_t word = 0;
        if (off >= 8u) word = le32(block + off);
        sum1 = (sum1 + word) % mod;
        sum2 = (sum2 + sum1) % mod;
    }
    return (sum2 << 32) | sum1;
}

int apfs_verify_checksum(const uint8_t *block, uint32_t block_len) {
    if (!block || block_len < APFS_BLOCK_MIN || (block_len & 3u) != 0u) {
        return -1;
    }
    return le64(block) == fletcher64(block, block_len) ? 1 : 0;
}

int apfs_parse_container_superblock(const uint8_t *block, uint32_t block_len,
                                    uint64_t block_number,
                                    apfs_container_info_t *out) {
    if (!block || !out || block_len < APFS_BLOCK_MIN || block_len < 984u ||
        !has_magic(block + 32u, APFS_MAGIC_NXSB)) return -1;

    uint32_t block_size = le32(block + 36u);
    uint64_t block_count = le64(block + 40u);
    uint32_t max_fs = le32(block + 180u);
    if (!is_power_of_two(block_size) || block_size < APFS_BLOCK_MIN ||
        block_size > APFS_BLOCK_MAX || block_count == 0u ||
        max_fs > APFS_MAX_VOLUMES) return -2;

    out->nx_block = block_number;
    out->block_size = block_size;
    out->block_count = block_count;
    out->incompatible_features = le64(block + 64u);
    out->xp_desc_base = le64(block + 112u);
    out->xp_desc_blocks = le32(block + 104u);
    out->max_file_systems = max_fs;
    for (unsigned i = 0; i < 16; i++) out->uuid[i] = block[72u + i];
    for (unsigned i = 0; i < APFS_MAX_VOLUMES; i++) {
        out->fs_oid[i] = le64(block + 184u + i * 8u);
    }
    out->checksum_valid = apfs_verify_checksum(block, block_len);
    return 0;
}

int apfs_parse_volume_superblock(const uint8_t *block, uint32_t block_len,
                                 uint64_t block_number,
                                 apfs_volume_info_t *out) {
    if (!block || !out || block_len < APFS_BLOCK_MIN || block_len < 960u ||
        !has_magic(block + 32u, APFS_MAGIC_APSB)) return -1;

    out->block = block_number;
    out->fs_index = le32(block + 36u);
    out->omap_oid = le64(block + 128u);
    out->root_tree_oid = le64(block + 136u);
    for (unsigned i = 0; i < 16; i++) out->uuid[i] = block[240u + i];
    for (unsigned i = 0; i < sizeof(out->name) - 1u; i++) {
        /* APFS stores the volume name as UTF-8/UTF-16 depending on the
         * producer. Preserve ASCII bytes and replace high bytes safely. */
        uint8_t c = block[704u + i];
        if (c == 0u) {
            out->name[i] = 0;
            break;
        }
        out->name[i] = (c < 0x80u) ? (char)c : '?';
        out->name[i + 1u] = 0;
    }
    out->name[sizeof(out->name) - 1u] = 0;
    out->checksum_valid = apfs_verify_checksum(block, block_len);
    return 0;
}

static int read_block(const apfs_io_t *io, uint64_t block, uint32_t size) {
    if (!io || !io->read_block || size < APFS_BLOCK_MIN ||
        size > APFS_BLOCK_MAX) return -1;
    for (uint32_t i = 0; i < size; i++) g_block[i] = 0;
    return io->read_block(io->context, block, g_block, size);
}

int apfs_find_volume(const apfs_io_t *io, const apfs_container_info_t *container,
                     uint32_t index, uint32_t scan_blocks,
                     apfs_volume_info_t *volume) {
    if (!io || !container || !volume || index >= APFS_MAX_VOLUMES) return -1;
    uint32_t bs = container->block_size;

    /* The checkpoint's fs_oid entries are physical object IDs on ordinary
     * containers. Try the direct address first; fallback scanning is useful
     * for captured images whose object map has not been resolved. */
    if (index < container->max_file_systems && container->fs_oid[index] != 0 &&
        container->fs_oid[index] < container->block_count &&
        read_block(io, container->fs_oid[index], bs) == 0 &&
        apfs_parse_volume_superblock(g_block, bs, container->fs_oid[index],
                                     volume) == 0 &&
        volume->fs_index == index) {
        return 0;
    }

    uint64_t limit = container->block_count;
    if (scan_blocks != 0u && limit > scan_blocks) limit = scan_blocks;
    if (limit > APFS_MAX_SCAN_BLOCKS) limit = APFS_MAX_SCAN_BLOCKS;
    for (uint64_t block = 0; block < limit; block++) {
        if (read_block(io, block, bs) != 0) continue;
        if (apfs_parse_volume_superblock(g_block, bs, block, volume) == 0 &&
            volume->fs_index == index) return 0;
    }
    return -2;
}

int apfs_open(const apfs_io_t *io, uint32_t scan_blocks,
              apfs_container_info_t *container, apfs_volume_info_t *volume) {
    if (!io || !container || !volume || !io->read_block) return -1;
    uint8_t first[APFS_BLOCK_MIN];
    if (io->read_block(io->context, 0, first, sizeof(first)) == 0 &&
        apfs_parse_container_superblock(first, sizeof(first), 0, container) == 0) {
        if (apfs_find_volume(io, container, 0, scan_blocks, volume) == 0) return 0;
        return 1; /* Container is valid even when it has no discoverable vol. */
    }

    uint32_t limit = scan_blocks == 0u ? 64u : scan_blocks;
    if (limit > APFS_MAX_SCAN_BLOCKS) limit = APFS_MAX_SCAN_BLOCKS;
    for (uint32_t block = 1; block < limit; block++) {
        if (io->read_block(io->context, block, first, sizeof(first)) != 0) continue;
        if (apfs_parse_container_superblock(first, sizeof(first), block,
                                            container) == 0) {
            if (apfs_find_volume(io, container, 0, scan_blocks, volume) == 0) return 0;
            return 1;
        }
    }
    return -2;
}

static int walk_node(const apfs_io_t *io, uint64_t block, uint32_t block_size,
                     unsigned depth, apfs_btree_entry_fn callback,
                     void *context) {
    if (depth >= APFS_MAX_WALK_DEPTH || read_block(io, block, block_size) != 0) {
        return -1;
    }

    uint16_t flags = le16(g_block + 32u);
    uint16_t level = le16(g_block + 34u);
    uint32_t nkeys = le32(g_block + 36u);
    uint16_t table_off = le16(g_block + 40u);
    uint16_t table_len = le16(g_block + 42u);
    uint32_t data_start = APFS_NODE_HEADER;
    uint32_t table_start = data_start + table_off;
    if (nkeys > 65535u || table_start > block_size ||
        table_len > block_size - table_start) return -2;
    if ((flags & APFS_FIXED_KV_FLAG) != 0u) {
        /* Fixed-key nodes require the root's btree_info for key/value sizes;
         * refusing them is safer than guessing and reading unrelated bytes. */
        return -3;
    }
    if ((uint32_t)table_len < nkeys * 8u) return -2;

    unsigned child_count = 0;
    for (uint32_t i = 0; i < nkeys; i++) {
        const uint8_t *toc = g_block + table_start + i * 8u;
        uint16_t key_off = le16(toc + 0u);
        uint16_t key_len = le16(toc + 2u);
        uint16_t value_off = le16(toc + 4u);
        uint16_t value_len = le16(toc + 6u);
        uint32_t key_end = data_start + key_off + key_len;
        uint32_t value_end = data_start + value_off + value_len;
        if (key_end > block_size || value_end > block_size) return -2;

        apfs_btree_entry_t entry = {
            g_block + data_start + key_off, key_len,
            g_block + data_start + value_off, value_len, level
        };
        if (callback && callback(&entry, context) != 0) return 1;
        if (level != 0u) {
            if (value_len < 8u) return -2;
            if (child_count >= APFS_MAX_NODE_CHILDREN) return -4;
            g_children[depth][child_count++] = le64(entry.value);
        }
    }
    /* Reading a child reuses g_block. Collecting child IDs first keeps the
     * parent TOC intact while the recursive walk visits each child. */
    for (unsigned i = 0; i < child_count; i++) {
        int rc = walk_node(io, g_children[depth][i], block_size, depth + 1u,
                           callback, context);
        if (rc != 0) return rc;
    }
    return 0;
}

int apfs_btree_walk(const apfs_io_t *io, uint64_t root_block,
                    uint32_t block_size, apfs_btree_entry_fn callback,
                    void *context) {
    if (!io || !io->read_block || !callback || root_block == 0 ||
        !is_power_of_two(block_size) || block_size < APFS_BLOCK_MIN ||
        block_size > APFS_BLOCK_MAX) return -1;
    return walk_node(io, root_block, block_size, 0, callback, context);
}

int apfs_decode_extent(uint64_t object_id, const uint8_t *value,
                       uint16_t value_len, apfs_extent_t *out) {
    if (!value || !out || value_len < 24u) return -1;
    out->object_id = object_id;
    out->logical_size = le64(value + 0u);
    out->physical_block = le64(value + 8u);
    out->physical_block_count = le64(value + 16u);
    out->crypto_id = value_len >= 28u ? le32(value + 24u) : 0u;
    if (out->physical_block_count == 0u || out->logical_size == 0u) return -2;
    return 0;
}

int apfs_read_extent(const apfs_io_t *io, const apfs_extent_t *extent,
                     uint32_t block_size, apfs_file_sink_fn sink,
                     void *context) {
    if (!io || !extent || !sink || !io->read_block ||
        !is_power_of_two(block_size) || block_size < APFS_BLOCK_MIN ||
        block_size > APFS_BLOCK_MAX || extent->physical_block_count == 0u ||
        extent->physical_block_count > UINT64_MAX / block_size) return -1;

    uint64_t available = extent->physical_block_count * block_size;
    if (extent->logical_size > available) return -2;
    uint64_t remaining = extent->logical_size;
    for (uint64_t i = 0; remaining != 0; i++) {
        if (io->read_block(io->context, extent->physical_block + i,
                           g_block, block_size) != 0) return -3;
        uint32_t amount = remaining < block_size ? (uint32_t)remaining
                                                  : block_size;
        if (sink(i * block_size, g_block, amount, context) != 0) return -4;
        remaining -= amount;
    }
    return 0;
}
