#ifndef GOAT_UTIL_H
#define GOAT_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* Byte-exact comparison that does not leak a match position through timing.
 * Signature and digest checks should not be trivially early-exiting. */
int goat_memeq(const void *a, const void *b, size_t len);

/* Big-endian helpers: the container stores integers and octet strings the
 * way DER does, big-endian, so unpacking to limb arrays needs these. */
void goat_load_be64(const uint8_t *in, unsigned limbs, uint64_t *out);
void goat_store_be64(uint8_t *out, unsigned limbs, const uint64_t *in);

/* Fixed-window hex dump of a buffer, used by the goat shell commands to
 * report container fields over the serial console. */
void goat_hex(const uint8_t *data, size_t len, char separator, char *out,
              size_t out_size);

#endif /* GOAT_UTIL_H */
