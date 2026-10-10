#ifndef RECFG_H
#define RECFG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define kRecfgFailure 0
#define kRecfgSuccess 1
#define kRecfgUpdate 2

#define RECFG_CMD_CMD_r(cmd)   (((cmd)[0] >> 24) & 0xff)
#define RECFG_CMD_META_r(cmd)  (((cmd)[0] >> 16) & 0xff)
#define RECFG_CMD_DATA_r(cmd)  ((cmd)[0] & 0xffff)
#define RECFG_CMD_DATA_w(cmd, val) ((cmd)[0] = (((cmd)[0] & ~0xffff) | ((val) & 0xffff)))

#define RECFG_READ_LARGE_r(read)     (((read)[0] >> 31) & 1)
#define RECFG_READ_BASE_r(read)      (((read)[0] >> 18) & 0x1fff)
#define RECFG_READ_OFF_r(read)       (((read)[0] >> 10) & 0xff)
#define RECFG_READ_RETRY_r(read)     (((read)[0] >> 9) & 1)
#define RECFG_READ_RECNT_r(read)     ((read)[0] & 0x1ff)

#define RECFG_READ_BASE_w(read, val) ((read)[0] = (((read)[0] & ~(0x1fff << 18)) | (((val) & 0x1fff) << 18)))
#define RECFG_READ_OFF_w(read, val)  ((read)[0] = (((read)[0] & ~(0xff << 10)) | (((val) & 0xff) << 10)))
#define RECFG_READ_RETRY_w(read, val) ((read)[0] = (((read)[0] & ~(1 << 9)) | (((val) & 1) << 9)))
#define RECFG_READ_RECNT_w(read, val) ((read)[0] = (((read)[0] & ~0x1ff) | ((val) & 0x1ff)))

#define RECFG_WRITE_COUNT_r(w32)     ((w32)[0] & 0xf)
#define RECFG_WRITE_BASE_r(w32)      (((w32)[0] >> 4) & 0x3fff)
#define RECFG_WRITE_OFF_r(w32, idx)  (((w32)[1 + (idx / 2)] >> (16 * (idx & 1))) & 0xff)
#define RECFG_WRITE_BASE_w(w32, val) ((w32)[0] = (((w32)[0] & ~(0x3fff << 4)) | (((val) & 0x3fff) << 4)))
#define RECFG_WRITE_OFF_w(w32, idx, val) \
    do { \
        uint32_t *w = &(w32)[1 + (idx / 2)]; \
        *w = (*w & ~(0xff << (16 * (idx & 1)))) | (((val) & 0xff) << (16 * (idx & 1))); \
    } while(0)

typedef struct {
    int (*generic)(void *a, uint32_t *cmd);
    int (*end)(void *a);
    int (*delay)(void *a, uint32_t *data);
    int (*r32)(void *a, uint64_t *addr, uint32_t *mask, uint32_t *data, bool *retry, uint8_t *recnt);
    int (*r64)(void *a, uint64_t *addr, uint64_t *mask, uint64_t *data, bool *retry, uint8_t *recnt);
    int (*w32)(void *a, uint64_t *addr, uint32_t *data);
    int (*w64)(void *a, uint64_t *addr, uint64_t *data);
} recfg_cb_t;

int recfg_check(void *mem, size_t size, size_t *offp, const bool warn);
int recfg_walk(void *mem, size_t size, const recfg_cb_t *cb, void *a);

void recfg_soc_setup(void);
void recfg_soc_sync(void);
void recfg_soc_lock(void);

#endif /* RECFG_H */