#ifndef SEPOS_H
#define SEPOS_H

#include <stdint.h>
#include "sep.h"

/*
 * SEP research shell wrappers.
 *
 * Protocol source: pongoOS src/drivers/sep/sep.c. All commands are
 * fail-closed: if the transport did not initialise they return the init
 * error rather than reporting success against a driver that stored nothing.
 */

/* Initialise the owned driver against the SoC profile's mailbox base. */
int sepos_init(void);

/* Dump whatever the SEP will tell us (ping, random). */
void dump_sepos(void);

/* SEP memory dump — requires SEPOS-side cooperation, not implemented. */
void sepos_memdump(uint64_t addr, uint32_t len);

/* Mailbox status and driver statistics. */
void sepos_status(void);

/* Shell command wrappers. */
int sepos_ping(void);
int sepos_get_random(void);
int sepos_boot_tz0(void);
int sepos_send_sepos(uint64_t image_phys, uint32_t image_size, uint64_t entry_phys);
int sepos_send_art(uint64_t art_phys, uint32_t art_size);
int sepos_enable_irq(void);

#endif /* SEPOS_H */