/* ---- dashboard: placed, grouped, paired, locked surfaces ----------------- */
    else if (strcmp(argv[0], "dash") == 0) {
        if (argc < 2) {
            uart_puts("Usage:\n");
            uart_puts("  dash scope <domain>                 Set current work; other surfaces are not offered\n");
            uart_puts("  dash list                           List in-scope surfaces and placements\n");
            uart_puts("  dash place <n> <col> <row> <w> <h>  Position and size\n");
            uart_puts("  dash move <n> <dcol> <drow>         Move; groups and pairs follow\n");
            uart_puts("  dash group <a> <b>                  Move together as one unit\n");
            uart_puts("  dash ungroup <n>\n");
            uart_puts("  dash pair <a> <b>                   Keep b at a fixed offset from a\n");
            uart_puts("  dash unpair <n>\n");
            uart_puts("  dash lock <n> / unlock <n>          Locking one locks its group\n");
            uart_puts("  dash tile [domain]                  Auto-arrange in-scope surfaces\n");
            uart_puts("  dash draw                           Render onto the framebuffer\n");
            uart_puts("  dash reset\n");
            uart_puts("domains: global storage usb periph crypto memory net display sep system\n");
            return;
        }
        if (strcmp(argv[1], "scope") == 0 && argc >= 3) {
            dash_domain_t d = dash_domain_from_name(argv[2]);
            if (d >= DASH_DOM_COUNT) { uart_puts("dash: unknown domain\n"); return; }
            dash_set_scope(d);
            uart_puts("dash: scope=");
            uart_puts(dash_domain_name(dash_scope()));
            uart_puts("\n");
        }
        else if (strcmp(argv[1], "list") == 0) {
            dash_report();
        }
        else if (strcmp(argv[1], "place") == 0 && argc >= 7) {
            int rc = dash_place(argv[2], (uint16_t)parse_hex(argv[3]),
                                (uint16_t)parse_hex(argv[4]),
                                (uint16_t)parse_hex(argv[5]),
                                (uint16_t)parse_hex(argv[6]));
            if (rc != 0) { uart_puts("dash: "); uart_puts(dash_error_string(rc)); uart_putc('\n'); }
        }
        else if (strcmp(argv[1], "move") == 0 && argc >= 5) {
            int rc = dash_move(argv[2], (int)parse_hex(argv[3]),
                               (int)parse_hex(argv[4]));
            if (rc != 0) { uart_puts("dash: "); uart_puts(dash_error_string(rc)); uart_putc('\n'); }
        }
        else if (strcmp(argv[1], "group") == 0 && argc >= 4) {
            int rc = dash_group(argv[2], argv[3]);
            if (rc != 0) { uart_puts("dash: "); uart_puts(dash_error_string(rc)); uart_putc('\n'); }
        }
        else if (strcmp(argv[1], "ungroup") == 0 && argc >= 3) {
            dash_ungroup(argv[2]);
        }
        else if (strcmp(argv[1], "pair") == 0 && argc >= 4) {
            int rc = dash_pair(argv[2], argv[3]);
            if (rc != 0) { uart_puts("dash: "); uart_puts(dash_error_string(rc)); uart_putc('\n'); }
        }
        else if (strcmp(argv[1], "unpair") == 0 && argc >= 3) {
            dash_unpair(argv[2]);
        }
        else if (strcmp(argv[1], "lock") == 0 && argc >= 3) {
            int rc = dash_lock(argv[2]);
            if (rc != 0) { uart_puts("dash: "); uart_puts(dash_error_string(rc)); uart_putc('\n'); }
        }
        else if (strcmp(argv[1], "unlock") == 0 && argc >= 3) {
            dash_unlock(argv[2]);
        }
        else if (strcmp(argv[1], "tile") == 0) {
            if (argc >= 3) {
                dash_domain_t d = dash_domain_from_name(argv[2]);
                if (d < DASH_DOM_COUNT) dash_set_scope(d);
            }
            int rc = dash_tile();
            if (rc == 0) {
                dash_draw();
                uart_puts("dash: tiled in-scope surfaces\n");
            } else {
                uart_puts("dash: tile failed: ");
                uart_puts(dash_error_string(rc));
                uart_putc('\n');
            }
        }
        else if (strcmp(argv[1], "draw") == 0) {
            dash_draw();
            uart_puts("dash: drawn\n");
        }
        else if (strcmp(argv[1], "reset") == 0) {
            dash_reset();
            uart_puts("dash: reset\n");
        }
        else {
            uart_puts("Unknown dash command. Type 'dash'\n");
        }
    }
