/* Recfg sequence parser and walker.
 *
 * Based on pongoOS recfg driver.
 */

#include "recfg.h"
#include "mmio.h"
#include "uart.h"
#include "util.h"
#include "string.h"

#define kRecfgMeta 0x00
#define kRecfgRead 0x01
#define kRecfgWrite32 0x02
#define kRecfgWrite64 0x03

#define kRecfgEnd 0x00
#define kRecfgDelay 0x01

int recfg_check(void *mem, size_t size, size_t *offp, const bool warn)
{
    int retval = kRecfgFailure;
    char *start = mem, *end = start + size;
    uint32_t *cmd = mem;

    while (end - (char*)cmd != 0) {
        if (end - (char*)cmd < 4) {
            if (warn) uart_puts("recfg: truncated command\n");
            goto out;
        }

        uint32_t cmd_type = RECFG_CMD_CMD_r(cmd);

        switch (cmd_type) {
            case kRecfgMeta: {
                uint32_t meta_type = RECFG_CMD_META_r(cmd);
                if (meta_type == kRecfgEnd) {
                    if (RECFG_CMD_DATA_r(cmd) != 0) {
                        if (warn) uart_puts("recfg: end with data\n");
                        goto out;
                    }
                    goto end;
                } else if (meta_type == kRecfgDelay) {
                    // OK
                } else {
                    if (warn) uart_puts("recfg: unknown meta type\n");
                    goto out;
                }
                cmd += 1;
                break;
            }
            case kRecfgRead: {
                if (end - (char*)cmd < 8) {
                    if (warn) uart_puts("recfg: truncated read command\n");
                    goto out;
                }
                uint32_t *read = cmd;
                if (!RECFG_READ_LARGE_r(read)) {
                    if (end - (char*)cmd < 8) {
                        if (warn) uart_puts("recfg: truncated read32\n");
                        goto out;
                    }
                    cmd += 2;
                } else {
                    if (end - (char*)cmd < 24) {
                        if (warn) uart_puts("recfg: truncated read64\n");
                        goto out;
                    }
                    cmd += 6;
                }
                break;
            }
            case kRecfgWrite32: {
                if (end - (char*)cmd < 8) {
                    if (warn) uart_puts("recfg: truncated write32 header\n");
                    goto out;
                }
                uint32_t *w32 = cmd;
                uint32_t cnt = RECFG_WRITE_COUNT_r(w32) + 1;
                uint32_t alcnt = (cnt + 3) & ~3;
                if (cnt > 16 || alcnt > 16 || (alcnt & 3) != 0) {
                    if (warn) uart_puts("recfg: write32 count sanity failed\n");
                    goto out;
                }
                size_t needed = 8 + alcnt + cnt * 4;
                if ((size_t)(end - (char*)cmd) < needed) {
                    if (warn) uart_puts("recfg: truncated write32 data\n");
                    goto out;
                }
                cmd += 2 + alcnt + cnt;
                break;
            }
            case kRecfgWrite64: {
                if (end - (char*)cmd < 8) {
                    if (warn) uart_puts("recfg: truncated write64 header\n");
                    goto out;
                }
                uint32_t *w64 = cmd;
                uint32_t cnt = RECFG_WRITE_COUNT_r(w64) + 1;
                uint32_t alcnt = (cnt + 3) & ~3;
                if (cnt > 16 || alcnt > 16 || (alcnt & 3) != 0) {
                    if (warn) uart_puts("recfg: write64 count sanity failed\n");
                    goto out;
                }
                size_t needed = 8 + alcnt + cnt * 8;
                if ((size_t)(end - (char*)cmd) < needed) {
                    if (warn) uart_puts("recfg: truncated write64 data\n");
                    goto out;
                }
                cmd += 2 + alcnt + cnt * 2;
                break;
            }
            default:
                if (warn) uart_puts("recfg: unknown command type\n");
                goto out;
        }
    }
end:
    retval = kRecfgSuccess;

out:
    if (offp) *offp = (char*)cmd - start;
    return retval;
}

int recfg_walk(void *mem, size_t size, const recfg_cb_t *cb, void *a)
{
    int retval = kRecfgFailure, ret = kRecfgSuccess;
    char *start = mem, *end = start + size;
    uint32_t *cmd = mem;

    while (end - (char*)cmd != 0) {
        if (cb->generic) {
            uint32_t copy = cmd[0];
            int r = cb->generic(a, &copy);
            if (r == kRecfgUpdate) {
                // Can't update generic
                retval = r;
                goto out;
            }
            if (r != kRecfgSuccess) {
                retval = r;
                goto out;
            }
        }

        uint32_t cmd_type = RECFG_CMD_CMD_r(cmd);

        switch (cmd_type) {
            case kRecfgMeta: {
                uint32_t meta_type = RECFG_CMD_META_r(cmd);
                if (meta_type == kRecfgEnd) {
                    if (cb->end) {
                        int r = cb->end(a);
                        if (r == kRecfgUpdate) {
                            retval = r;
                            goto out;
                        }
                        if (r != kRecfgSuccess) {
                            retval = r;
                            goto out;
                        }
                    }
                    goto end;
                } else if (meta_type == kRecfgDelay) {
                    if (cb->delay) {
                        uint32_t data = RECFG_CMD_DATA_r(cmd);
                        int r = cb->delay(a, &data);
                        if (r == kRecfgUpdate) {
                            if (data >= (1 << 26)) {
                                retval = kRecfgFailure;
                                goto out;
                            }
                            RECFG_CMD_DATA_w(cmd, data);
                            ret |= kRecfgUpdate;
                        } else if (r != kRecfgSuccess) {
                            retval = r;
                            goto out;
                        }
                    }
                } else {
                    goto out;
                }
                cmd += 1;
                break;
            }
            case kRecfgRead: {
                uint32_t *read = cmd;
                if (!RECFG_READ_LARGE_r(read)) {
                    uint32_t *r32 = read;
                    if (cb->r32) {
                        uint64_t addr = ((uint64_t)RECFG_READ_BASE_r(r32) << 10) | ((uint64_t)RECFG_READ_OFF_r(r32) << 2);
                        uint32_t mask = r32[1] >> 16;
                        uint32_t data = r32[1] & 0xffff;
                        bool retry = (r32[0] >> 9) & 1;
                        uint8_t recnt = r32[0] & 0x1ff;
                        int r = cb->r32(a, &addr, &mask, &data, &retry, &recnt);
                        if (r == kRecfgUpdate) {
                            if ((addr & 0xfffffff000000003) != 0) {
                                retval = kRecfgFailure;
                                goto out;
                            }
                            RECFG_READ_BASE_w(r32, addr >> 10);
                            RECFG_READ_OFF_w(r32, (addr >> 2) & 0xff);
                            r32[1] = (mask << 16) | (data & 0xffff);
                            r32[0] = (r32[0] & ~((1 << 9) | 0x1ff)) | ((retry ? 1 : 0) << 9) | (recnt & 0x1ff);
                            ret |= kRecfgUpdate;
                        } else if (r != kRecfgSuccess) {
                            retval = r;
                            goto out;
                        }
                    }
                    cmd += 2;
                } else {
                    // 64-bit read
                    uint32_t *r64 = read;
                    uint32_t *tmp = r64 + 1;
                    // Check alignment
                    if (((uintptr_t)tmp & 0x4) != 0) {
                        tmp++;
                    }
                    uint64_t *datap = (uint64_t*)tmp;
                    if (cb->r64) {
                        uint64_t addr = ((uint64_t)RECFG_READ_BASE_r(r64) << 10) | ((uint64_t)RECFG_READ_OFF_r(r64) << 2);
                        uint64_t mask = datap[0];
                        uint64_t data = datap[1];
                        bool retry = (r64[0] >> 9) & 1;
                        uint8_t recnt = r64[0] & 0x1ff;
                        int r = cb->r64(a, &addr, &mask, &data, &retry, &recnt);
                        if (r == kRecfgUpdate) {
                            if ((addr & 0xfffffff000000003) != 0) {
                                retval = kRecfgFailure;
                                goto out;
                            }
                            RECFG_READ_BASE_w(r64, addr >> 10);
                            RECFG_READ_OFF_w(r64, (addr >> 2) & 0xff);
                            datap[0] = mask;
                            datap[1] = data;
                            r64[0] = (r64[0] & ~((1 << 9) | 0x1ff)) | ((retry ? 1 : 0) << 9) | (recnt & 0x1ff);
                            ret |= kRecfgUpdate;
                        } else if (r != kRecfgSuccess) {
                            retval = r;
                            goto out;
                        }
                    }
                    cmd += 6;
                }
                break;
            }
            case kRecfgWrite32: {
                uint32_t *w32 = cmd;
                uint32_t cnt = RECFG_WRITE_COUNT_r(w32) + 1;
                uint32_t alcnt = (cnt + 3) & ~3;
                uint32_t *datap = (uint32_t*)((uint8_t*)(w32 + 1) + alcnt);
                if (cb->w32) {
                    for (uint32_t i = 0; i < cnt; ++i) {
                        uint64_t addr = ((uint64_t)RECFG_WRITE_BASE_r(w32) << 10) | ((uint64_t)RECFG_WRITE_OFF_r(w32, i) << 2);
                        uint32_t data = datap[i];
                        int r = cb->w32(a, &addr, &data);
                        if (r == kRecfgUpdate) {
                            if ((addr & 0xfffffff000000003) != 0) {
                                retval = kRecfgFailure;
                                goto out;
                            }
                            if (cnt == 1) {
                                RECFG_WRITE_BASE_w(w32, addr >> 10);
                            } else {
                                if ((addr & 0xffffffc00) != (RECFG_WRITE_BASE_r(w32) << 10)) {
                                    retval = kRecfgFailure;
                                    goto out;
                                }
                            }
                            RECFG_WRITE_OFF_w(w32, i, (addr >> 2) & 0xff);
                            datap[i] = data;
                            ret |= kRecfgUpdate;
                        } else if (r != kRecfgSuccess) {
                            retval = r;
                            goto out;
                        }
                    }
                }
                cmd += 2 + alcnt + cnt;
                break;
            }
            case kRecfgWrite64: {
                uint32_t *w64 = cmd;
                uint32_t cnt = RECFG_WRITE_COUNT_r(w64) + 1;
                uint32_t alcnt = (cnt + 3) & ~3;
                uint32_t *tmp = (uint32_t*)((uint8_t*)(w64 + 1) + alcnt);
                if (((uintptr_t)tmp & 0x4) != 0) {
                    tmp++;
                }
                uint64_t *datap = (uint64_t*)tmp;
                if (cb->w64) {
                    for (uint32_t i = 0; i < cnt; ++i) {
                        uint64_t addr = ((uint64_t)RECFG_WRITE_BASE_r(w64) << 10) | ((uint64_t)RECFG_WRITE_OFF_r(w64, i) << 2);
                        uint64_t data = datap[i];
                        int r = cb->w64(a, &addr, &data);
                        if (r == kRecfgUpdate) {
                            if ((addr & 0xfffffff000000003) != 0) {
                                retval = kRecfgFailure;
                                goto out;
                            }
                            if (cnt == 1) {
                                RECFG_WRITE_BASE_w(w64, addr >> 10);
                            } else {
                                if ((addr & 0xffffffc00) != (RECFG_WRITE_BASE_r(w64) << 10)) {
                                    retval = kRecfgFailure;
                                    goto out;
                                }
                            }
                            RECFG_WRITE_OFF_w(w64, i, (addr >> 2) & 0xff);
                            datap[i] = data;
                            ret |= kRecfgUpdate;
                        } else if (r != kRecfgSuccess) {
                            retval = r;
                            goto out;
                        }
                    }
                }
                cmd += 2 + alcnt + cnt * 2;
                break;
            }
            default:
                goto out;
        }
    }
end:
    retval = ret;

out:
    return retval;
}