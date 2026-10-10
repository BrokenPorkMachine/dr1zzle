/* Host tests for the dashboard layout engine.
 *
 * The layout rules are the part worth testing without hardware: scope
 * filtering, group moves, pair offsets, group locking, collision and range
 * rejection, and tiling. Rendering is stubbed out; what is exercised is the
 * geometry logic that decides where things go.
 */

#include "dashboard.h"

#include <stdio.h>
#include <string.h>
#include "console.h"
#include "dashboard_stubs.h"

#include <stdio.h>
#include <string.h>

static const char *out;
static int failures;
static int checks;

static void check(int condition, const char *what) {
    checks++;
    if (!condition) {
        failures++;
        printf("  FAIL: %s\n", what);
    }
}

static void check_rc(int rc, int want, const char *what) {
    checks++;
    if (rc != want) {
        failures++;
        printf("  FAIL: %s (rc=%d want=%d)\n", what, rc, want);
    }
}

static void at(const char *name, int col, int row, const char *what) {
    const dash_surface_t *s = dash_find(name);
    check(s != 0, what);
    if (!s) return;
    checks++;
    if (s->col != col || s->row != row) {
        failures++;
        printf("  FAIL: %s: %s at %d,%d want %d,%d\n",
               what, name, s->col, s->row, col, row);
    }
}

#include "dashboard_stubs.h"

int main(void) {
    printf("dashboard layout tests\n");

    /* --- scoping ------------------------------------------------------- */
    printf(" scoping\n");
    dash_init();
    dash_set_scope(DASH_DOM_STORAGE);

    check(dash_in_scope(dash_find("nand")), "nand is in storage scope");
    check(dash_in_scope(dash_find("status")), "global surface is always in scope");
    check(!dash_in_scope(dash_find("usb")), "usb is not in storage scope");
    check(!dash_in_scope(dash_find("gpio")), "gpio is not in storage scope");

    /* The central claim: a surface outside the current work is not offered,
     * not merely greyed. Operating on it is refused. */
    check_rc(dash_place("usb", 0, 0, 4, 4), DASH_ERR_SCOPE,
             "out-of-scope surface cannot be placed");
    check_rc(dash_move("gpio", 1, 1), DASH_ERR_SCOPE,
             "out-of-scope surface cannot be moved");
    check_rc(dash_lock("gpio"), DASH_ERR_SCOPE,
             "out-of-scope surface cannot be locked");
    check(dash_find("gpio") != 0, "out-of-scope surface still exists");

    dash_set_scope(DASH_DOM_USB);
    check(dash_in_scope(dash_find("usb")), "usb is in usb scope");
    check(!dash_in_scope(dash_find("nand")), "nand is not in usb scope");

    /* --- grouping ----------------------------------------------------- */
    printf(" grouping\n");
    dash_init();
    dash_set_scope(DASH_DOM_STORAGE);
    /* Park the pair somewhere empty first: in the default layout nand sits
     * hard against apfs, so a one-cell move would collide -- correctly. */
    dash_place("rom", 0, 12, 8, 4);
    dash_place("nand", 10, 12, 8, 4);
    dash_group("rom", "nand");
    check_rc(dash_move("rom", 1, 0), DASH_OK, "group member moves");
    at("rom", 1, 12, "rom moved");
    at("nand", 11, 12, "grouped nand followed rom");

    /* a refused move must not apply partially */
    checks++;
    if (dash_move("rom", 100, 0) == DASH_OK) {
        failures++;
        printf("  FAIL: move off-grid should be refused\n");
    }
    at("rom", 1, 12, "rom did not move on refused group move");

    dash_ungroup("nand");
    dash_move("nand", 1, 0);
    at("nand", 12, 12, "ungrouped nand moves alone");
    at("rom", 1, 12, "rom stayed put after nand ungrouped");

    /* --- pairing ------------------------------------------------------ */
    printf(" pairing\n");
    dash_init();
    dash_set_scope(DASH_DOM_STORAGE);
    /* Park both in empty rows: the default layout has rom against nand and
     * apfs against nand, so a legal move has nowhere to go. */
    dash_place("rom", 0, 12, 8, 4);
    dash_place("apfs", 22, 12, 8, 4);
    dash_pair("rom", "apfs");
    /* rom at 0,4 and apfs at 22,4: offset is +22,+0 */
    dash_move("rom", 0, 1);
    at("rom", 0, 13, "rom moved");
    at("apfs", 22, 13, "paired apfs kept its offset");

    dash_move("rom", 1, 0);
    at("apfs", 23, 13, "paired apfs followed rom again");

    dash_unpair("rom");
    dash_move("rom", 0, 1);
    at("apfs", 23, 13, "apfs stayed after unpair");

    /* --- pairing a grouped surface must not double-move ---------------- */
    printf(" pair+group interaction\n");
    dash_init();
    dash_set_scope(DASH_DOM_STORAGE);
    dash_place("rom", 0, 12, 8, 4);
    dash_place("nand", 10, 12, 8, 4);
    dash_place("apfs", 22, 12, 8, 4);
    dash_group("rom", "nand");
    dash_pair("rom", "apfs");
    dash_move("rom", 0, 1);
    at("rom", 0, 13, "rom moved");
    at("nand", 10, 13, "grouped nand followed");
    at("apfs", 22, 13, "paired apfs kept its offset exactly once");

    /* --- locking ------------------------------------------------------ */
    printf(" locking\n");
    dash_init();
    dash_set_scope(DASH_DOM_STORAGE);
    dash_place("rom", 0, 12, 8, 4);
    dash_place("nand", 10, 12, 8, 4);
    dash_group("rom", "nand");
    dash_lock("nand");
    check_rc(dash_move("rom", 1, 0), DASH_ERR_LOCKED,
             "group is locked through one member");
    at("rom", 0, 12, "locked group did not move");

    dash_unlock("rom");
    check_rc(dash_move("rom", 1, 0), DASH_OK, "unlocked group moves again");

    dash_lock("apfs");
    check_rc(dash_place("apfs", 0, 0, 4, 4), DASH_ERR_LOCKED,
             "locked surface cannot be placed");

    /* --- range and collision ------------------------------------------ */
    printf(" range and collision\n");
    dash_init();
    dash_set_scope(DASH_DOM_STORAGE);
    check_rc(dash_place("nand", 30, 0, 8, 4), DASH_ERR_RANGE,
             "placement past the right edge is refused");
    check_rc(dash_place("nand", 0, 17, 4, 4), DASH_ERR_RANGE,
             "placement past the bottom edge is refused");
    check_rc(dash_place("nand", 0, 0, 4, 4), DASH_ERR_COLLIDE,
             "overlapping 'status' is refused");
    check_rc(dash_place("nothing", 0, 0, 1, 1), DASH_ERR_UNKNOWN,
             "unknown surface is refused");
    check_rc(dash_group("rom", "rom"), DASH_ERR_SELF,
             "cannot group a surface with itself");

    /* --- tile --------------------------------------------------------- */
    printf(" tiling\n");
    dash_init();
    dash_set_scope(DASH_DOM_PERIPH);
    dash_tile();
    {
        const char *names[4] = { "gpio", "i2c", "spi", "wdog" };
        int on_grid = 1;
        for (int i = 0; i < 4; i++) {
            const dash_surface_t *s = dash_find(names[i]);
            if (!s) continue;
            if (s->col + s->cols > DASH_COLS || s->row + s->rows > DASH_ROWS) {
                on_grid = 0;
            }
        }
        check(on_grid, "tiled surfaces fit the grid");
    }
    /* tile must not be refused merely because a locked surface exists */
    dash_lock("gpio");
    check_rc(dash_tile(), DASH_OK, "tile succeeds with a locked surface present");

    /* --- report ------------------------------------------------------- */
    printf(" report\n");
    dash_init();
    dash_set_scope(DASH_DOM_STORAGE);
    dashboard_test_output_clear();
    dash_report();
    out = dashboard_test_output();
    check(strstr(out, "scope=storage") != 0, "report names the scope");
    check(strstr(out, "nand") != 0, "report lists an in-scope surface");
    check(strstr(out, "usb") == 0,
          "report does not list an out-of-scope surface");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures != 0;
}
