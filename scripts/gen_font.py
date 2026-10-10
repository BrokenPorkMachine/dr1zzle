#!/usr/bin/env python3
"""Generate the 8x8 console font as a C table.

Glyphs are authored here as ASCII art so they can be reviewed and rendered
without a device. Run this to regenerate src/drivers/font8x8.c:

    python3 scripts/gen_font.py > src/drivers/font8x8.c

`tests/test_hw.py` re-renders the checked-in table back to ASCII art and
asserts it matches this file, so the two cannot drift.
"""

import sys

GLYPH_W, GLYPH_H = 5, 7
CELL_W, CELL_H = 6, 8
FIRST, LAST = 0x20, 0x7E

# fmt: off
GLYPHS = {
 ' ': ("     ", "     ", "     ", "     ", "     ", "     ", "     "),
 '!': ("  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "     ", "  #  "),
 '"': (" # # ", " # # ", "     ", "     ", "     ", "     ", "     "),
 '#': (" # # ", " # # ", "#####", " # # ", "#####", " # # ", " # # "),
 '$': ("  #  ", " ####", "# #  ", " ### ", "  # #", "#### ", "  #  "),
 '%': ("##  #", "##  #", "   # ", "  #  ", " #   ", "#  ##", "#  ##"),
 '&': (" ##  ", "#  # ", "# #  ", " #   ", "# # #", "#  # ", " ## #"),
 "'": ("  #  ", "  #  ", "     ", "     ", "     ", "     ", "     "),
 '(': ("   # ", "  #  ", " #   ", " #   ", " #   ", "  #  ", "   # "),
 ')': (" #   ", "  #  ", "   # ", "   # ", "   # ", "  #  ", " #   "),
 '*': ("     ", "# # #", " ### ", "#####", " ### ", "# # #", "     "),
 '+': ("     ", "  #  ", "  #  ", "#####", "  #  ", "  #  ", "     "),
 ',': ("     ", "     ", "     ", "     ", "  ## ", "  #  ", " #   "),
 '-': ("     ", "     ", "     ", "#####", "     ", "     ", "     "),
 '.': ("     ", "     ", "     ", "     ", "     ", "  ## ", "  ## "),
 '/': ("    #", "   # ", "   # ", "  #  ", " #   ", " #   ", "#    "),
 '0': (" ### ", "#   #", "#  ##", "# # #", "##  #", "#   #", " ### "),
 '1': ("  #  ", " ##  ", "  #  ", "  #  ", "  #  ", "  #  ", " ### "),
 '2': (" ### ", "#   #", "    #", "   # ", "  #  ", " #   ", "#####"),
 '3': ("#####", "   # ", "  #  ", "   # ", "    #", "#   #", " ### "),
 '4': ("   # ", "  ## ", " # # ", "#  # ", "#####", "   # ", "   # "),
 '5': ("#####", "#    ", "#### ", "    #", "    #", "#   #", " ### "),
 '6': ("  ## ", " #   ", "#    ", "#### ", "#   #", "#   #", " ### "),
 '7': ("#####", "    #", "   # ", "  #  ", " #   ", " #   ", " #   "),
 '8': (" ### ", "#   #", "#   #", " ### ", "#   #", "#   #", " ### "),
 '9': (" ### ", "#   #", "#   #", " ####", "    #", "   # ", " ##  "),
 ':': ("     ", "  ## ", "  ## ", "     ", "  ## ", "  ## ", "     "),
 ';': ("     ", "  ## ", "  ## ", "     ", "  ## ", "  #  ", " #   "),
 '<': ("   # ", "  #  ", " #   ", "#    ", " #   ", "  #  ", "   # "),
 '=': ("     ", "     ", "#####", "     ", "#####", "     ", "     "),
 '>': (" #   ", "  #  ", "   # ", "    #", "   # ", "  #  ", " #   "),
 '?': (" ### ", "#   #", "    #", "   # ", "  #  ", "     ", "  #  "),
 '@': (" ### ", "#   #", "# ###", "# # #", "# ###", "#    ", " ### "),
 'A': ("  #  ", " # # ", "#   #", "#   #", "#####", "#   #", "#   #"),
 'B': ("#### ", "#   #", "#   #", "#### ", "#   #", "#   #", "#### "),
 'C': (" ### ", "#   #", "#    ", "#    ", "#    ", "#   #", " ### "),
 'D': ("###  ", "#  # ", "#   #", "#   #", "#   #", "#  # ", "###  "),
 'E': ("#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#####"),
 'F': ("#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#    "),
 'G': (" ### ", "#   #", "#    ", "# ###", "#   #", "#   #", " ### "),
 'H': ("#   #", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"),
 'I': (" ### ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", " ### "),
 'J': ("  ###", "   # ", "   # ", "   # ", "   # ", "#  # ", " ##  "),
 'K': ("#   #", "#  # ", "# #  ", "##   ", "# #  ", "#  # ", "#   #"),
 'L': ("#    ", "#    ", "#    ", "#    ", "#    ", "#    ", "#####"),
 'M': ("#   #", "## ##", "# # #", "# # #", "#   #", "#   #", "#   #"),
 'N': ("#   #", "#   #", "##  #", "# # #", "#  ##", "#   #", "#   #"),
 'O': (" ### ", "#   #", "#   #", "#   #", "#   #", "#   #", " ### "),
 'P': ("#### ", "#   #", "#   #", "#### ", "#    ", "#    ", "#    "),
 'Q': (" ### ", "#   #", "#   #", "#   #", "# # #", "#  # ", " ## #"),
 'R': ("#### ", "#   #", "#   #", "#### ", "# #  ", "#  # ", "#   #"),
 'S': (" ####", "#    ", "#    ", " ### ", "    #", "    #", "#### "),
 'T': ("#####", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  "),
 'U': ("#   #", "#   #", "#   #", "#   #", "#   #", "#   #", " ### "),
 'V': ("#   #", "#   #", "#   #", "#   #", "#   #", " # # ", "  #  "),
 'W': ("#   #", "#   #", "#   #", "# # #", "# # #", "## ##", "#   #"),
 'X': ("#   #", "#   #", " # # ", "  #  ", " # # ", "#   #", "#   #"),
 'Y': ("#   #", "#   #", " # # ", "  #  ", "  #  ", "  #  ", "  #  "),
 'Z': ("#####", "    #", "   # ", "  #  ", " #   ", "#    ", "#####"),
 '[': (" ### ", " #   ", " #   ", " #   ", " #   ", " #   ", " ### "),
 '\\':("#    ", " #   ", " #   ", "  #  ", "   # ", "   # ", "    #"),
 ']': (" ### ", "   # ", "   # ", "   # ", "   # ", "   # ", " ### "),
 '^': ("  #  ", " # # ", "#   #", "     ", "     ", "     ", "     "),
 '_': ("     ", "     ", "     ", "     ", "     ", "     ", "#####"),
 '`': (" #   ", "  #  ", "     ", "     ", "     ", "     ", "     "),
 'a': ("     ", "     ", " ### ", "    #", " ####", "#   #", " ####"),
 'b': ("#    ", "#    ", "#### ", "#   #", "#   #", "#   #", "#### "),
 'c': ("     ", "     ", " ### ", "#    ", "#    ", "#   #", " ### "),
 'd': ("    #", "    #", " ####", "#   #", "#   #", "#   #", " ####"),
 'e': ("     ", "     ", " ### ", "#   #", "#####", "#    ", " ### "),
 'f': ("  ## ", " #  #", " #   ", "#### ", " #   ", " #   ", " #   "),
 'g': ("     ", " ####", "#   #", "#   #", " ####", "    #", " ### "),
 'h': ("#    ", "#    ", "#### ", "#   #", "#   #", "#   #", "#   #"),
 'i': ("  #  ", "     ", " ##  ", "  #  ", "  #  ", "  #  ", " ### "),
 'j': ("   # ", "     ", "  ## ", "   # ", "   # ", "#  # ", " ##  "),
 'k': ("#    ", "#    ", "#  # ", "# #  ", "##   ", "# #  ", "#  # "),
 'l': (" ##  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", " ### "),
 'm': ("     ", "     ", "## # ", "# # #", "# # #", "#   #", "#   #"),
 'n': ("     ", "     ", "#### ", "#   #", "#   #", "#   #", "#   #"),
 'o': ("     ", "     ", " ### ", "#   #", "#   #", "#   #", " ### "),
 'p': ("     ", "#### ", "#   #", "#   #", "#### ", "#    ", "#    "),
 'q': ("     ", " ####", "#   #", "#   #", " ####", "    #", "    #"),
 'r': ("     ", "     ", "# ## ", "##  #", "#    ", "#    ", "#    "),
 's': ("     ", "     ", " ####", "#    ", " ### ", "    #", "#### "),
 't': (" #   ", " #   ", "#### ", " #   ", " #   ", " #  #", "  ## "),
 'u': ("     ", "     ", "#   #", "#   #", "#   #", "#  ##", " ## #"),
 'v': ("     ", "     ", "#   #", "#   #", "#   #", " # # ", "  #  "),
 'w': ("     ", "     ", "#   #", "#   #", "# # #", "# # #", " # # "),
 'x': ("     ", "     ", "#   #", " # # ", "  #  ", " # # ", "#   #"),
 'y': ("     ", "#   #", "#   #", "#   #", " ####", "    #", " ### "),
 'z': ("     ", "     ", "#####", "   # ", "  #  ", " #   ", "#####"),
 '{': ("   # ", "  #  ", "  #  ", " #   ", "  #  ", "  #  ", "   # "),
 '|': ("  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  "),
 '}': (" #   ", "  #  ", "  #  ", "   # ", "  #  ", "  #  ", " #   "),
 '~': ("     ", "     ", " #  #", "# # #", "#  # ", "     ", "     "),
}
# fmt: on


def glyph_rows(ch):
    art = GLYPHS[ch]
    if len(art) != GLYPH_H:
        raise SystemExit(f"glyph {ch!r} has {len(art)} rows, want {GLYPH_H}")
    for row in art:
        if len(row) != GLYPH_W:
            raise SystemExit(f"glyph {ch!r} row {row!r} is {len(row)} wide, want {GLYPH_W}")
        if set(row) - set("# "):
            raise SystemExit(f"glyph {ch!r} has characters other than '#' and ' '")
    return art


def to_bytes(art):
    """Pack a 5x7 glyph into a 6x8 cell, one byte per row, LSB = leftmost."""
    out = []
    for y in range(CELL_H):
        bits = 0
        if y < GLYPH_H:
            row = art[y]
            for x in range(GLYPH_W):
                if row[x] == "#":
                    bits |= 1 << x
        out.append(bits)
    return out


def render_table(fbytes):
    """Inverse of to_bytes, for auditing the checked-in table."""
    rows = []
    for code in range(FIRST, LAST + 1):
        base = (code - FIRST) * CELL_H
        cell = fbytes[base : base + CELL_H]
        art = []
        for y in range(GLYPH_H):
            bits = cell[y]
            art.append("".join("#" if bits & (1 << x) else " " for x in range(GLYPH_W)))
        rows.append(art)
    return rows


def emit(fbytes):
    print("/* Generated by scripts/gen_font.py -- do not edit by hand. */")
    print("/* 5x7 glyphs in a 6x8 cell, ASCII 0x20-0x7E, one byte per row. */")
    print()
    print('#include "display.h"')
    print()
    print("const uint8_t font8x8[FONT_LAST - FONT_FIRST + 1][FONT_CELL_H] = {")
    for code in range(FIRST, LAST + 1):
        ch = chr(code)
        cell = to_bytes(glyph_rows(ch))
        disp = ch if ch != "\\" else "\\\\"
        bytes_s = ", ".join(f"0x{b:02X}" for b in cell)
        print(f"    {{ {bytes_s} }},  /* 0x{code:02X} {disp} */")
    print("};")
    print()


def main():
    missing = [chr(c) for c in range(FIRST, LAST + 1) if chr(c) not in GLYPHS]
    if missing:
        raise SystemExit("missing glyphs: " + " ".join(repr(m) for m in missing))

    fbytes = []
    for code in range(FIRST, LAST + 1):
        fbytes.extend(to_bytes(glyph_rows(chr(code))))

    if "--portable" in sys.argv:
        print("/* Generated by scripts/gen_font.py --portable. */")
        print('#include <drizzle/display.h>')
        print("const uint8_t drizzle_display_font[128][8] = {")
        for code in range(FIRST, LAST + 1):
            rows = to_bytes(glyph_rows(chr(code)))
            # Portable renderer uses bit 7 for the leftmost pixel.
            rows = [sum(((row >> x) & 1) << (7 - x) for x in range(8)) for row in rows]
            print(f"    [0x{code:02x}] = {{ " + ", ".join(f"0x{row:02x}" for row in rows) + " },")
        print("};")
    elif "--render" in sys.argv:
        want = "".join(sys.argv[sys.argv.index("--render") + 1 :]) or "Research> 0123 ABCdef ghi!"
        lines = {}
        for ch in want:
            code = ord(ch)
            if not FIRST <= code <= LAST:
                continue
            art = render_table(fbytes)[code - FIRST]
            for y in range(GLYPH_H):
                lines.setdefault(y, [])
                lines[y].append(art[y])
        for y in sorted(lines):
            print("|".join(lines[y]))
    else:
        emit(fbytes)


if __name__ == "__main__":
    main()
