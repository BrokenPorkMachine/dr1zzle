/* IMG4/KBAG parser.
 *
 * KBAG payloads occur in both a DER sequence form and an older fixed-width
 * capture form. This parser accepts both, but never follows a length without
 * checking it against the caller-provided buffer. GID decryption is an
 * internal validation only: hardware-derived key bytes are never printed or
 * returned to the shell.
 */

#include "keybag.h"

#include "aes.h"
#include "uart.h"
#include "util.h"

#define DER_SEQUENCE 0x30u
#define DER_INTEGER 0x02u
#define DER_OCTETS 0x04u
#define KBAG_WRAP_GID 0u

typedef struct {
    uint8_t tag;
    const uint8_t *content;
    uint32_t length;
    uint32_t total;
} kb_tlv_t;

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wipe_bytes(uint8_t *data, uint32_t length) {
    volatile uint8_t *p = data;
    while (length--) *p++ = 0;
}

static int tlv_read(const uint8_t *data, uint32_t len, kb_tlv_t *out) {
    if (!data || !out || len < 2u) return -1;
    uint32_t index = 1u;
    uint32_t content_len;
    uint8_t first = data[index++];
    if (first < 0x80u) {
        content_len = first;
    } else {
        uint32_t octets = first & 0x7fu;
        if (octets == 0u || octets > 4u || index + octets > len) return -1;
        content_len = 0;
        for (uint32_t i = 0; i < octets; i++) {
            if (i == 0u && data[index] == 0u && octets > 1u) return -1;
            content_len = (content_len << 8) | data[index++];
        }
    }
    if (content_len > len - index) return -1;
    out->tag = data[0];
    out->content = data + index;
    out->length = content_len;
    out->total = index + content_len;
    return 0;
}

static int scalar(const kb_tlv_t *tlv, uint32_t *value) {
    if (!tlv || !value || tlv->length == 0u || tlv->length > 4u ||
        (tlv->tag != DER_INTEGER && tlv->tag != DER_OCTETS)) return -1;
    uint32_t result = 0;
    for (uint32_t i = 0; i < tlv->length; i++) result = (result << 8) | tlv->content[i];
    *value = result;
    return 0;
}

static int add_entry(keybag_entry_t *entries, uint32_t capacity,
                     uint32_t *count, const kb_tlv_t *wrap,
                     const kb_tlv_t *klass, const kb_tlv_t *size,
                     const kb_tlv_t *iv, const kb_tlv_t *cipher) {
    if (!entries || !count || *count >= capacity || !wrap || !klass ||
        !size || !iv || !cipher || iv->tag != DER_OCTETS || iv->length != 16u ||
        cipher->tag != DER_OCTETS || cipher->length == 0u ||
        cipher->length > KEYBAG_MAX_KEY_BYTES || (cipher->length & 15u) != 0u) {
        return -1;
    }
    keybag_entry_t *entry = &entries[*count];
    for (unsigned i = 0; i < sizeof(*entry); i++) ((uint8_t *)entry)[i] = 0;
    if (scalar(wrap, &entry->wrap_type) != 0 ||
        scalar(klass, &entry->key_class) != 0 ||
        scalar(size, &entry->key_size) != 0) return -1;
    if (entry->key_size != 0u && entry->key_size != cipher->length) return -1;
    for (unsigned i = 0; i < 16; i++) entry->iv[i] = iv->content[i];
    for (uint32_t i = 0; i < cipher->length; i++) entry->wrapped[i] = cipher->content[i];
    entry->wrapped_len = cipher->length;
    (*count)++;
    return 0;
}

static int parse_der_sequence(const uint8_t *data, uint32_t len,
                              keybag_entry_t *entries, uint32_t capacity,
                              uint32_t *count, unsigned depth) {
    if (depth > 8u) return -1;
    kb_tlv_t root;
    if (tlv_read(data, len, &root) != 0 || root.tag != DER_SEQUENCE) return -1;

    kb_tlv_t children[8];
    uint32_t child_count = 0, offset = 0;
    while (offset < root.length && child_count < 8u) {
        if (tlv_read(root.content + offset, root.length - offset,
                     &children[child_count]) != 0) return -1;
        offset += children[child_count].total;
        child_count++;
    }
    if (offset != root.length) return -1;

    if (child_count >= 5u && children[3].tag == DER_OCTETS &&
        children[4].tag == DER_OCTETS) {
        (void)add_entry(entries, capacity, count, &children[0], &children[1],
                        &children[2], &children[3], &children[4]);
    }
    uint32_t child_offset = 0;
    for (uint32_t i = 0; i < child_count; i++) {
        if (children[i].tag == DER_SEQUENCE) {
            (void)parse_der_sequence(root.content + child_offset,
                                     root.length - child_offset, entries,
                                     capacity, count, depth + 1u);
        }
        child_offset += children[i].total;
    }
    return 0;
}

static int parse_legacy(const uint8_t *data, uint32_t len,
                        keybag_entry_t *entries, uint32_t capacity,
                        uint32_t *count) {
    uint32_t offset = 0;
    while (offset + 28u <= len && *count < capacity) {
        uint32_t key_size = le32(data + offset + 8u);
        if (key_size == 0u || key_size > KEYBAG_MAX_KEY_BYTES ||
            (key_size & 15u) != 0u || offset + 28u + key_size > len) break;
        keybag_entry_t *entry = &entries[*count];
        for (unsigned i = 0; i < sizeof(*entry); i++) ((uint8_t *)entry)[i] = 0;
        entry->wrap_type = le32(data + offset);
        entry->key_class = le32(data + offset + 4u);
        entry->key_size = key_size;
        for (unsigned i = 0; i < 16; i++) entry->iv[i] = data[offset + 12u + i];
        for (uint32_t i = 0; i < key_size; i++) entry->wrapped[i] = data[offset + 28u + i];
        entry->wrapped_len = key_size;
        (*count)++;
        offset += 28u + key_size;
    }
    return *count != 0u ? 0 : -1;
}

int keybag_parse(const uint8_t *data, uint32_t len,
                 keybag_entry_t *entries, uint32_t capacity,
                 uint32_t *count) {
    if (!data || !entries || !count || capacity == 0u) return -1;
    *count = 0;
    for (uint32_t i = 0; i + 4u <= len; i++) {
        if (data[i] != 'K' || data[i + 1] != 'B' || data[i + 2] != 'A' ||
            data[i + 3] != 'G') continue;
        if (i + 4u < len && data[i + 4u] == DER_SEQUENCE &&
            parse_der_sequence(data + i + 4u, len - i - 4u,
                               entries, capacity, count, 0u) == 0 && *count != 0u) {
            return 0;
        }
        if (parse_legacy(data + i + 4u, len - i - 4u, entries, capacity,
                         count) == 0) return 0;
    }
    if (len != 0u && data[0] == DER_SEQUENCE &&
        parse_der_sequence(data, len, entries, capacity, count, 0u) == 0 &&
        *count != 0u) return 0;
    return parse_legacy(data, len, entries, capacity, count);
}

int keybag_decrypt_entries(keybag_entry_t *entries, uint32_t count) {
    if (!entries || count > KEYBAG_MAX_ENTRIES) return -1;
    int decrypted = 0;
    for (uint32_t i = 0; i < count; i++) {
        keybag_entry_t *entry = &entries[i];
        if (entry->wrap_type != KBAG_WRAP_GID) continue;
        uint8_t chain[16];
        uint8_t decrypted_key[KEYBAG_MAX_KEY_BYTES];
        for (unsigned j = 0; j < 16; j++) chain[j] = entry->iv[j];
        int ok = 1;
        for (uint32_t off = 0; off < entry->wrapped_len; off += 16u) {
            uint8_t cipher[16];
            for (unsigned j = 0; j < 16; j++) cipher[j] = entry->wrapped[off + j];
            if (aes_crypt_block(AES_KEY_GID, 1, cipher, decrypted_key + off,
                                chain) != 0) {
                ok = 0;
                break;
            }
            for (unsigned j = 0; j < 16; j++) chain[j] = cipher[j];
        }
        wipe_bytes(decrypted_key, KEYBAG_MAX_KEY_BYTES);
        entry->decrypted_valid = ok;
        if (ok) decrypted++;
    }
    return decrypted;
}

static void print_entry(const keybag_entry_t *entry, uint32_t index) {
    uart_puts("  entry "); uart_puts(utoa(index));
    uart_puts(" class=0x"); uart_puts(utoa_hex(entry->key_class));
    uart_puts(" wrap=0x"); uart_puts(utoa_hex(entry->wrap_type));
    uart_puts(" bytes="); uart_puts(utoa(entry->wrapped_len));
    uart_puts(entry->decrypted_valid ? " gid-check=ok\n" : " gid-check=unavailable\n");
}

void decrypt_keybag(const uint8_t *img4_data, uint32_t len) {
    keybag_entry_t entries[KEYBAG_MAX_ENTRIES];
    uint32_t count = 0;
    if (keybag_parse(img4_data, len, entries, KEYBAG_MAX_ENTRIES, &count) != 0) {
        uart_puts("keybag: no supported KBAG entries\n");
        return;
    }
    int decrypted = keybag_decrypt_entries(entries, count);
    uart_puts("keybag: "); uart_puts(utoa(count)); uart_puts(" entries, ");
    uart_puts(utoa(decrypted)); uart_puts(" GID checks passed\n");
    for (uint32_t i = 0; i < count; i++) print_entry(&entries[i], i);
}

void parse_kbag(const uint8_t *kbag, uint32_t len) {
    decrypt_keybag(kbag, len);
}

void decrypt_keybag_from_file(const char *path) {
    (void)path;
    uart_puts("keybag: file input is not available in bare metal; pass IMG4 bytes as hex\n");
}
