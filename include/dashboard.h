#ifndef DR1ZZLE_DASHBOARD_H
#define DR1ZZLE_DASHBOARD_H

#include <stdint.h>

/* Research dashboard: placed, grouped, paired and locked surfaces.
 *
 * ---------------------------------------------------------------------------
 * The idea
 * ---------------------------------------------------------------------------
 *
 * The payload has a lot of independent subsystems, and the interesting work
 * is always in a subset of them. A flat command list makes you scroll past
 * twenty things that have nothing to do with the NAND problem you are
 * actually chasing. So surfaces carry a domain, and there is a current scope:
 * only surfaces in scope (plus global ones) are listed, moved, tiled or
 * offered by any operation. A surface outside your scope is not shown at all
 * rather than shown greyed out -- you never have to skip past it.
 *
 * Layout operations on top of that:
 *
 *   place  position and size a surface on the grid
 *   group  move a set together as one unit
 *   pair   keep one surface at a fixed offset from another
 *   lock   make a surface, or a whole group, immovable
 *   tile   auto-arrange the in-scope surfaces
 *
 * Geometry is in grid cells, not pixels, so a layout typed on one panel
 * survives a different framebuffer resolution.
 */

#define DASH_COLS 32
#define DASH_ROWS 18
#define DASH_MAX_SURFACES 24

typedef enum {
    DASH_DOM_GLOBAL = 0,   /* always in scope, whatever you are doing */
    DASH_DOM_STORAGE,      /* nand, apfs, securerom */
    DASH_DOM_USB,          /* usb, cdc */
    DASH_DOM_PERIPH,       /* gpio, i2c, spi, watchdog */
    DASH_DOM_CRYPTO,       /* aes, keybag, key material */
    DASH_DOM_MEMORY,       /* memory dumps */
    DASH_DOM_NET,          /* ethernet, tcp, telnet */
    DASH_DOM_DISPLAY,      /* panel, framebuffer */
    DASH_DOM_SEP,          /* sep, mailbox */
    DASH_DOM_SYSTEM,       /* clocks, interrupts, panics */
    DASH_DOM_COUNT
} dash_domain_t;

typedef struct {
    const char *name;
    uint8_t     domain;
    uint8_t     group;     /* 0 = ungrouped; group members share a move */
    uint8_t     pair;      /* index of the partner, DASH_NO_PAIR if none */
    uint8_t     locked;
    uint16_t    col, row;      /* grid position  */
    uint16_t    cols, rows;    /* grid extent    */
} dash_surface_t;

#define DASH_NO_PAIR 0xFF

void dash_init(void);

/* Scope: the current work. Surfaces outside it are not offered. */
void dash_set_scope(dash_domain_t domain);
dash_domain_t dash_scope(void);
int dash_in_scope(const dash_surface_t *s);
const char *dash_domain_name(dash_domain_t domain);
dash_domain_t dash_domain_from_name(const char *name);

dash_surface_t *dash_find(const char *name);

/* Layout operations. Each returns 0, or a negative reason code. */
enum {
    DASH_OK = 0,
    DASH_ERR_UNKNOWN = -1,     /* no such surface */
    DASH_ERR_SCOPE = -2,      /* surface is not in the current scope */
    DASH_ERR_LOCKED = -3,      /* surface or its group is locked */
    DASH_ERR_RANGE = -4,       /* geometry would leave the grid */
    DASH_ERR_COLLIDE = -5,    /* overlaps another surface */
    DASH_ERR_SELF = -6        /* group/pair with itself */
};

int dash_place(const char *name, uint16_t col, uint16_t row,
               uint16_t cols, uint16_t rows);
int dash_move(const char *name, int dcol, int drow);
int dash_group(const char *a, const char *b);
int dash_ungroup(const char *name);
int dash_pair(const char *a, const char *b);
int dash_unpair(const char *name);
int dash_lock(const char *name);
int dash_unlock(const char *name);
int dash_tile(void);
int dash_reset(void);

/* Draw the in-scope surfaces onto the attached framebuffer. */
void dash_draw(void);

/* Console listing, on the serial/net console. */
void dash_report(void);
const char *dash_error_string(int rc);

#endif /* DR1ZZLE_DASHBOARD_H */
