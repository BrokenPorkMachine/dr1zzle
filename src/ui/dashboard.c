/* Dashboard: placed, grouped, paired and locked surfaces over the framebuffer.
 *
 * ---------------------------------------------------------------------------
 * Layout model
 * ---------------------------------------------------------------------------
 *
 * A surface occupies a rectangle of grid cells. Three relations bind
 * surfaces together, deliberately in increasing strength:
 *
 *   group  a shared id. Moving any member moves every member by the same
 *          delta. The relative arrangement is whatever it was.
 *   pair   a partner id plus a fixed relative offset captured when the pair
 *          was made. Moving one moves the partner so the offset is preserved
 *          exactly -- the two stay glued edge to edge or criss-crossed however
 *          they were paired.
 *   lock   immovability. Locking a member locks its whole group, because a
 *          group that can be dragged apart by one member is not locked.
 *
 * Scoping sits in front of all of it: a surface outside the current scope is
 * not listed, not moved, not tiled, and not offered as a target. The point is
 * that you never have to look past surfaces unrelated to the current work.
 *
 * Tile walks the in-scope, unlocked surfaces and packs them left to right,
 * top to bottom, into the widest rectangle that fits the grid. It does not
 * attempt a perfect packing; it attempts a predictable one you can then
 * adjust by hand.
 */

#include "dashboard.h"
#include "display.h"
#include "console.h"
#include "string.h"
#include "util.h"

#define DASH_MAX_GROUPS 8
#define DASH_NO_GROUP   0

typedef struct {
    dash_surface_t s;
    int16_t pair_dcol;     /* partner offset captured at pair time */
    int16_t pair_drow;
} dash_entry_t;

static dash_entry_t surfaces[DASH_MAX_SURFACES];
static unsigned surface_count;
static dash_domain_t current_scope = DASH_DOM_GLOBAL;
static unsigned next_group = 1;

/* Surface table: the payload's real subsystems, each in the domain it
 * belongs to. A surface with DOM_GLOBAL is offered in every scope. */
static const dash_surface_t initial[] = {
    { "status",  DASH_DOM_GLOBAL,   0, DASH_NO_PAIR, 1,  0, 0, 32, 4 },
    { "rom",     DASH_DOM_STORAGE,  0, DASH_NO_PAIR, 0,  0, 4, 10, 5 },
    { "nand",    DASH_DOM_STORAGE,  0, DASH_NO_PAIR, 0, 10, 4, 12, 8 },
    { "apfs",    DASH_DOM_STORAGE,  0, DASH_NO_PAIR, 0, 22, 4, 10, 6 },
    { "usb",     DASH_DOM_USB,      0, DASH_NO_PAIR, 0,  0, 9, 12, 5 },
    { "cdc",     DASH_DOM_USB,      0, DASH_NO_PAIR, 0, 12, 9, 10, 5 },
    { "gpio",    DASH_DOM_PERIPH,   0, DASH_NO_PAIR, 0,  0, 14,  8, 4 },
    { "i2c",     DASH_DOM_PERIPH,   0, DASH_NO_PAIR, 0,  8, 14,  6, 4 },
    { "spi",     DASH_DOM_PERIPH,   0, DASH_NO_PAIR, 0, 14, 14,  6, 4 },
    { "wdog",    DASH_DOM_PERIPH,   0, DASH_NO_PAIR, 0, 20, 14,  6, 4 },
    { "aes",     DASH_DOM_CRYPTO,   0, DASH_NO_PAIR, 0,  0, 18,  9, 0 },
    { "keybag",  DASH_DOM_CRYPTO,   0, DASH_NO_PAIR, 0,  9, 18,  9, 0 },
    { "mem",     DASH_DOM_MEMORY,   0, DASH_NO_PAIR, 0, 18, 18, 14, 0 },
    { "net",     DASH_DOM_NET,      0, DASH_NO_PAIR, 0,  0, 22, 10, 0 },
    { "display", DASH_DOM_DISPLAY,  0, DASH_NO_PAIR, 0, 10, 22, 10, 0 },
    { "sep",     DASH_DOM_SEP,      0, DASH_NO_PAIR, 0, 20, 22, 12, 0 },
    { "sys",     DASH_DOM_SYSTEM,   0, DASH_NO_PAIR, 0,  0, 26, 32, 0 },
};

#define INITIAL_COUNT (sizeof(initial) / sizeof(initial[0]))

static const char *domain_names[DASH_DOM_COUNT] = {
    "global", "storage", "usb", "periph", "crypto",
    "memory", "net", "display", "sep", "system"
};

const char *dash_domain_name(dash_domain_t domain) {
    if (domain >= DASH_DOM_COUNT) return "?";
    return domain_names[domain];
}

dash_domain_t dash_domain_from_name(const char *name) {
    for (int i = 0; i < DASH_DOM_COUNT; i++) {
        if (strcmp(domain_names[i], name) == 0) return (dash_domain_t)i;
    }
    return DASH_DOM_COUNT;
}

int dash_in_scope(const dash_surface_t *s) {
    if (s->domain == DASH_DOM_GLOBAL) return 1;
    return s->domain == current_scope;
}

/* --- helpers ------------------------------------------------------------- */

static dash_entry_t *find_entry(const char *name) {
    for (unsigned i = 0; i < surface_count; i++) {
        if (strcmp(surfaces[i].s.name, name) == 0) return &surfaces[i];
    }
    return 0;
}

/* A group is locked when any of its members is locked: you cannot drag a
 * group apart by grabbing the unlocked half. */
static int group_is_locked(dash_entry_t *e) {
    if (e->s.locked) return 1;
    if (e->s.group == DASH_NO_GROUP) return 0;
    for (unsigned i = 0; i < surface_count; i++) {
        if (surfaces[i].s.group == e->s.group && surfaces[i].s.locked) return 1;
    }
    return 0;
}

static int overlaps(const dash_surface_t *a, const dash_surface_t *b) {
    if (a == b) return 0;
    if (a->cols == 0 || a->rows == 0 || b->cols == 0 || b->rows == 0) return 0;
    return a->col < b->col + b->cols && b->col < a->col + a->cols &&
           a->row < b->row + b->rows && b->row < a->row + a->rows;
}

/* Does index i belong to the same move unit as e? Ungrouped surfaces are
 * their own unit; grouped surfaces share one. */
static int same_unit(const dash_entry_t *e, unsigned i) {
    if (e->s.group != DASH_NO_GROUP) return surfaces[i].s.group == e->s.group;
    return i == (unsigned)(e - surfaces);
}

static int fits_grid(const dash_surface_t *s) {
    return s->col + s->cols <= DASH_COLS && s->row + s->rows <= DASH_ROWS;
}

static int fits_anywhere(const dash_surface_t *candidate,
                         const char *ignore_name) {
    for (unsigned i = 0; i < surface_count; i++) {
        if (strcmp(surfaces[i].s.name, ignore_name) == 0) continue;
        /* Out-of-scope surfaces do not take part in the current layout at
         * all -- not drawn, not offered, and not in the way. Otherwise the
         * NAND work would be blocked by wherever the GPIO surface happened to
         * be parked, which is precisely what scoping is supposed to prevent. */
        if (!dash_in_scope(&surfaces[i].s)) continue;
        if (overlaps(candidate, &surfaces[i].s)) return 0;
    }
    return 1;
}

/* --- scope and init ------------------------------------------------------ */

void dash_set_scope(dash_domain_t domain) {
    if (domain >= DASH_DOM_COUNT) return;
    current_scope = domain;
}

dash_domain_t dash_scope(void) { return current_scope; }

void dash_init(void) {
    surface_count = 0;
    next_group = 1;
    for (unsigned i = 0; i < INITIAL_COUNT && i < DASH_MAX_SURFACES; i++) {
        surfaces[surface_count].s = initial[i];
        surfaces[surface_count].pair_dcol = 0;
        surfaces[surface_count].pair_drow = 0;
        surface_count++;
    }
    current_scope = DASH_DOM_GLOBAL;
}

dash_surface_t *dash_find(const char *name) {
    dash_entry_t *e = find_entry(name);
    return e ? &e->s : 0;
}

/* --- operations ---------------------------------------------------------- */

int dash_place(const char *name, uint16_t col, uint16_t row,
               uint16_t cols, uint16_t rows) {
    dash_entry_t *e = find_entry(name);
    if (!e) return DASH_ERR_UNKNOWN;
    if (!dash_in_scope(&e->s)) return DASH_ERR_SCOPE;
    if (e->s.locked) return DASH_ERR_LOCKED;

    dash_surface_t candidate = e->s;
    candidate.col = col;
    candidate.row = row;
    candidate.cols = cols;
    candidate.rows = rows;
    if (!fits_grid(&candidate)) return DASH_ERR_RANGE;
    if (!fits_anywhere(&candidate, name)) return DASH_ERR_COLLIDE;

    e->s = candidate;
    /* Re-anchor any pair so the captured offset stays meaningful. */
    if (e->s.pair != DASH_NO_PAIR) {
        dash_entry_t *p = &surfaces[e->s.pair];
        e->pair_dcol = (int16_t)(p->s.col - e->s.col);
        e->pair_drow = (int16_t)(p->s.row - e->s.row);
    }
    return DASH_OK;
}

int dash_move(const char *name, int dcol, int drow) {
    dash_entry_t *e = find_entry(name);
    if (!e) return DASH_ERR_UNKNOWN;
    if (!dash_in_scope(&e->s)) return DASH_ERR_SCOPE;
    if (group_is_locked(e)) return DASH_ERR_LOCKED;

    /* Move the group as a unit, checking the whole arrangement fits before
     * committing any of it -- a half-applied move is worse than a refused one. */
    for (unsigned i = 0; i < surface_count; i++) {
        if (!same_unit(e, i)) continue;

        dash_surface_t candidate = surfaces[i].s;
        candidate.col = (uint16_t)(candidate.col + dcol);
        candidate.row = (uint16_t)(candidate.row + drow);
        if (!fits_grid(&candidate)) return DASH_ERR_RANGE;
        if (!fits_anywhere(&candidate, candidate.name)) return DASH_ERR_COLLIDE;
    }

    for (unsigned i = 0; i < surface_count; i++) {
        if (!same_unit(e, i)) continue;
        surfaces[i].s.col = (uint16_t)(surfaces[i].s.col + dcol);
        surfaces[i].s.row = (uint16_t)(surfaces[i].s.row + drow);
    }

    /* A paired partner keeps its exact offset, so it moves by the same delta
     * as the surface it is paired with. Skip it when it already moved as part
     * of the group, or the delta would be applied twice. */
    if (e->s.pair != DASH_NO_PAIR) {
        dash_entry_t *p = &surfaces[e->s.pair];
        int already = (e->s.group != DASH_NO_GROUP && p->s.group == e->s.group);
        if (!already) {
            p->s.col = (uint16_t)(e->s.col + e->pair_dcol);
            p->s.row = (uint16_t)(e->s.row + e->pair_drow);
        }
    }
    return DASH_OK;
}

int dash_group(const char *a, const char *b) {
    dash_entry_t *ea = find_entry(a);
    dash_entry_t *eb = find_entry(b);
    if (!ea || !eb) return DASH_ERR_UNKNOWN;
    if (ea == eb) return DASH_ERR_SELF;
    if (!dash_in_scope(&ea->s) || !dash_in_scope(&eb->s)) return DASH_ERR_SCOPE;

    unsigned group = ea->s.group;
    if (group == DASH_NO_GROUP) {
        group = next_group++;
        ea->s.group = (uint8_t)group;
    }
    eb->s.group = (uint8_t)group;
    return DASH_OK;
}

int dash_ungroup(const char *name) {
    dash_entry_t *e = find_entry(name);
    if (!e) return DASH_ERR_UNKNOWN;
    if (!dash_in_scope(&e->s)) return DASH_ERR_SCOPE;
    e->s.group = DASH_NO_GROUP;
    return DASH_OK;
}

int dash_pair(const char *a, const char *b) {
    dash_entry_t *ea = find_entry(a);
    dash_entry_t *eb = find_entry(b);
    if (!ea || !eb) return DASH_ERR_UNKNOWN;
    if (ea == eb) return DASH_ERR_SELF;
    if (!dash_in_scope(&ea->s) || !dash_in_scope(&eb->s)) return DASH_ERR_SCOPE;

    ea->s.pair = (uint8_t)(eb - surfaces);
    eb->s.pair = (uint8_t)(ea - surfaces);
    ea->pair_dcol = (int16_t)(eb->s.col - ea->s.col);
    ea->pair_drow = (int16_t)(eb->s.row - ea->s.row);
    eb->pair_dcol = (int16_t)(ea->s.col - eb->s.col);
    eb->pair_drow = (int16_t)(ea->s.row - eb->s.row);
    return DASH_OK;
}

int dash_unpair(const char *name) {
    dash_entry_t *e = find_entry(name);
    if (!e) return DASH_ERR_UNKNOWN;
    if (e->s.pair != DASH_NO_PAIR) {
        surfaces[e->s.pair].s.pair = DASH_NO_PAIR;
    }
    e->s.pair = DASH_NO_PAIR;
    e->pair_dcol = 0;
    e->pair_drow = 0;
    return DASH_OK;
}

int dash_lock(const char *name) {
    dash_entry_t *e = find_entry(name);
    if (!e) return DASH_ERR_UNKNOWN;
    if (!dash_in_scope(&e->s)) return DASH_ERR_SCOPE;

    /* Locking a member locks the group: otherwise the group could still be
     * dragged apart through its unlocked members. */
    for (unsigned i = 0; i < surface_count; i++) {
        if (!same_unit(e, i)) continue;
        surfaces[i].s.locked = 1;
    }
    return DASH_OK;
}

int dash_unlock(const char *name) {
    dash_entry_t *e = find_entry(name);
    if (!e) return DASH_ERR_UNKNOWN;
    if (!dash_in_scope(&e->s)) return DASH_ERR_SCOPE;
    for (unsigned i = 0; i < surface_count; i++) {
        if (!same_unit(e, i)) continue;
        surfaces[i].s.locked = 0;
    }
    return DASH_OK;
}

int dash_tile(void) {
    /* Pack the in-scope, unlocked surfaces into a near-square block. */
    unsigned candidates[DASH_MAX_SURFACES];
    unsigned n = 0;
    for (unsigned i = 0; i < surface_count; i++) {
        if (!dash_in_scope(&surfaces[i].s)) continue;
        if (group_is_locked(&surfaces[i])) continue;
        candidates[n++] = i;
    }
    if (n == 0) return DASH_ERR_SCOPE;

    unsigned cols = 1;
    while (cols * cols < n) cols++;
    if (cols > DASH_COLS) cols = DASH_COLS;

    unsigned cell_w = DASH_COLS / cols;
    unsigned rows = (n + cols - 1) / cols;
    unsigned cell_h = DASH_ROWS / rows;

    for (unsigned k = 0; k < n; k++) {
        dash_entry_t *e = &surfaces[candidates[k]];
        e->s.col = (uint16_t)((k % cols) * cell_w);
        e->s.row = (uint16_t)((k / cols) * cell_h);
        e->s.cols = (uint16_t)cell_w;
        e->s.rows = (uint16_t)cell_h;
    }
    return DASH_OK;
}

int dash_reset(void) {
    dash_init();
    return DASH_OK;
}

const char *dash_error_string(int rc) {
    switch (rc) {
        case DASH_OK:          return "ok";
        case DASH_ERR_UNKNOWN: return "no such surface";
        case DASH_ERR_SCOPE:   return "not in the current scope";
        case DASH_ERR_LOCKED:  return "locked";
        case DASH_ERR_RANGE:   return "outside the grid";
        case DASH_ERR_COLLIDE: return "overlaps another surface";
        case DASH_ERR_SELF:    return "cannot bind a surface to itself";
        default:               return "error";
    }
}

/* --- draw ---------------------------------------------------------------- */

static uint32_t dash_color(uint8_t domain) {
    static const uint32_t palette[DASH_DOM_COUNT] = {
        0xff808080,  /* global  */
        0xffff8000,  /* storage */
        0xff0080ff,  /* usb     */
        0xff00c000,  /* periph  */
        0xffc000c0,  /* crypto  */
        0xffc0c000,  /* memory  */
        0xff00c0c0,  /* net     */
        0xffff4040,  /* display */
        0xff8040ff,  /* sep     */
        0xffd0d0d0,  /* system  */
    };
    return palette[domain];
}

static void dash_glyph(uint32_t x, uint32_t y, char c, uint32_t color) {
    uint8_t code = (uint8_t)c;
    if (code < FONT_FIRST || code > FONT_LAST) return;
    const uint8_t *glyph = font8x8[code - FONT_FIRST];
    for (uint32_t row = 0; row < FONT_GLYPH_H; row++) {
        uint8_t bits = glyph[row];
        if (!bits) continue;
        for (uint32_t bit = 0; bit < FONT_GLYPH_W; bit++) {
            if (bits & (1u << bit)) display_fb_pixel(x + bit, y + row, color);
        }
    }
}

static void dash_text(uint32_t x, uint32_t y, const char *s, uint32_t color) {
    while (*s) {
        dash_glyph(x, y, *s++, color);
        x += FONT_CELL_W;
    }
}

void dash_draw(void) {
    const display_fb_t *fb = display_fb();
    if (!fb) return;

    uint32_t cell_w = fb->width / DASH_COLS;
    uint32_t cell_h = fb->height / DASH_ROWS;
    if (cell_w == 0 || cell_h == 0) return;

    for (unsigned i = 0; i < surface_count; i++) {
        const dash_surface_t *s = &surfaces[i].s;

        /* Only in-scope surfaces are drawn. Out-of-scope surfaces are not
         * rendered faintly; they are absent. */
        if (!dash_in_scope(s)) continue;
        if (s->cols == 0 || s->rows == 0) continue;

        uint32_t x = s->col * cell_w;
        uint32_t y = s->row * cell_h;
        uint32_t w = s->cols * cell_w;
        uint32_t h = s->rows * cell_h;
        uint32_t color = dash_color(s->domain);

        display_fb_fill_rect(x, y, w, h, 0xff101010);
        display_fb_stroke_rect(x, y, w, h, color);

        uint32_t tx = x + 2;
        uint32_t ty = y + 2;
        dash_text(tx, ty, s->name, color);

        if (s->locked) {
            dash_text(x + w - FONT_CELL_W * 4, ty, "LCK", 0xff404040);
        }
        if (s->group != DASH_NO_GROUP) {
            char tag[6];
            tag[0] = 'G';
            tag[1] = (char)('0' + (s->group % 10));
            tag[2] = 0;
            dash_text(tx, ty + FONT_CELL_H, tag, color);
        }
        if (s->pair != DASH_NO_PAIR) {
            dash_text(tx + FONT_CELL_W * 3, ty + FONT_CELL_H, "<>", color);
        }
    }
}

/* --- console report ------------------------------------------------------ */

void dash_report(void) {
    console_puts("dash: scope=");
    console_puts(dash_domain_name(current_scope));
    console_puts("  (in-scope surfaces only)\n");

    for (unsigned i = 0; i < surface_count; i++) {
        const dash_surface_t *s = &surfaces[i].s;
        if (!dash_in_scope(s)) continue;

        console_puts("  ");
        console_puts(s->name);
        int pad = 8 - (int)strlen(s->name);
        while (pad-- > 0) console_putc(' ');

        console_putc('@');
        console_put_uint(s->col);
        console_putc(',');
        console_put_uint(s->row);
        console_putc(' ');
        console_put_uint(s->cols);
        console_putc('x');
        console_put_uint(s->rows);

        if (s->group != DASH_NO_GROUP) {
            console_puts(" grp=");
            console_put_uint(s->group);
        }
        if (s->pair != DASH_NO_PAIR) {
            console_puts(" pair=");
            console_puts(surfaces[s->pair].s.name);
        }
        if (s->locked) console_puts(" LOCKED");
        console_putc('\n');
    }

    console_puts("dash: ");
    console_put_uint(surface_count);
    console_puts(" surfaces total, ");
    console_puts(dash_domain_name(current_scope));
    console_puts(" in scope\n");
}
