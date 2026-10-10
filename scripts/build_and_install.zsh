#!/bin/zsh
# build_and_install.zsh — build dr1zzle + goat + usbr34ker, package them, install goat
#
# Usage:  ./scripts/build_and_install.zsh [--skip-usbr34ker] [--skip-install]
#
# Builds all three components, creates a self-contained package at
# ~/.dr1zzle-toolkit, then prompts to install the goat launcher onto PATH
# so it runs as `goat` (no leading ./).

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
DR1ZZLE_DIR="/Users/failbr34k/WORK/dr1zzle"
USBR34KER_DIR="${HOME}/Downloads/iphemeral-latest/usbr34ker"
TOOLKIT_DIR="${HOME}/.dr1zzle-toolkit"
GOAT_BIN="${TOOLKIT_DIR}/bin/goat"

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_BLUE=$'\033[0;34m'; C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[1;33m'
    C_RED=$'\033[0;31m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_BOLD=""; C_RESET=""
fi

info()    { print "${C_BLUE}==>${C_RESET} $*"; }
ok()      { print "${C_GREEN}✓${C_RESET} $*"; }
warn()    { print "${C_YELLOW}!${C_RESET} $*"; }
die()     { print "${C_RED}✗${C_RESET} $*" >&2; exit 1; }
section() { print "\n${C_BOLD}── $* ──${C_RESET}"; }

# ── Parse flags ──────────────────────────────────────────────────────────────
SKIP_USBR34KER=0
SKIP_INSTALL=0
for arg in "$@"; do
    case $arg in
        --skip-usbr34ker) SKIP_USBR34KER=1 ;;
        --skip-install)   SKIP_INSTALL=1 ;;
        *) warn "Unknown flag: $arg" ;;
    esac
done

# ── Prerequisite checks ──────────────────────────────────────────────────────
section "Checking prerequisites"

# dr1zzle needs: clang (aarch64 target), llvm tools
command -v clang >/dev/null 2>&1 || die "clang not found — install Xcode CLT"
[[ -d /opt/homebrew/opt/llvm/bin ]] || die "llvm tools not found — brew install llvm"
ok "clang + llvm tools"

# goat needs: python3, libusb
command -v python3 >/dev/null 2>&1 || die "python3 not found"
python3 -c "import ctypes.util; ctypes.util.find_library('usb-1.0')" >/dev/null 2>&1 \
    && ok "python3 + libusb" \
    || warn "python3 found but libusb missing — goat USB commands will fail (brew install libusb)"

# usbr34ker needs: Pico SDK, cmake, arm-none-eabi-gcc with newlib
if [[ $SKIP_USBR34KER -eq 0 ]]; then
    [[ -d "${HOME}/pico-sdk" ]] || die "Pico SDK not found at ~/pico-sdk"
    command -v cmake >/dev/null 2>&1 || die "cmake not found — brew install cmake"
    command -v arm-none-eabi-gcc >/dev/null 2>&1 || die "arm-none-eabi-gcc not found — brew install arm-none-eabi-gcc"
    ok "Pico SDK + cmake + arm-none-eabi-gcc"
fi

# ── 1. Build dr1zzle ─────────────────────────────────────────────────────────
section "Building dr1zzle"
cd "$DR1ZZLE_DIR"

info "Building core + firmware..."
make clean >/dev/null 2>&1 || true
make all -j"$(sysctl -n hw.ncpu)"

[[ -f build/a11-payload.bin ]] || die "core binary missing after build"
[[ -f build/firmware/dr1zzle.bin ]] || die "firmware binary missing after build"
ok "dr1zzle core  ($(wc -c <build/a11-payload.bin | tr -d ' ') bytes)"
ok "dr1zzle firmware ($(wc -c <build/firmware/dr1zzle.bin | tr -d ' ') bytes)"

# ── 2. Build usbr34ker ───────────────────────────────────────────────────────
if [[ $SKIP_USBR34KER -eq 0 ]]; then
    section "Building usbr34ker (5 boards — this takes a while)"
    cd "$USBR34KER_DIR"
    ./build_release.sh
    ok "usbr34ker built"
else
    section "Skipping usbr34ker build (--skip-usbr34ker)"
fi

# ── 3. Create package ────────────────────────────────────────────────────────
section "Creating package at ${TOOLKIT_DIR}"

rm -rf "$TOOLKIT_DIR"
mkdir -p "$TOOLKIT_DIR"/{bin,lib/goat,dr1zzle,usbr34ker}

# dr1zzle artifacts
cp "$DR1ZZLE_DIR/build/a11-payload.bin"   "$TOOLKIT_DIR/dr1zzle/"
cp "$DR1ZZLE_DIR/build/firmware/dr1zzle.bin" "$TOOLKIT_DIR/dr1zzle/"

# goat Python package
cp -R "$DR1ZZLE_DIR/goat/" "$TOOLKIT_DIR/lib/goat/"
rm -rf "$TOOLKIT_DIR/lib/goat/__pycache__" "$TOOLKIT_DIR/lib/goat/build"

# usbr34ker .uf2 artifacts
if [[ $SKIP_USBR34KER -eq 0 ]]; then
    cp "$USBR34KER_DIR"/artifacts/*.uf2 "$TOOLKIT_DIR/usbr34ker/" 2>/dev/null \
        || cp "$USBR34KER_DIR"/dist/*.uf2    "$TOOLKIT_DIR/usbr34ker/" 2>/dev/null \
        || warn "No .uf2 files found — check usbr34ker build output"
fi

# goat launcher wrapper
cat > "$GOAT_BIN" << 'LAUNCHER'
#!/usr/bin/env bash
# goat launcher — installed by dr1zzle build_and_install.zsh
TOOLKIT="${HOME}/.dr1zzle-toolkit"
export PYTHONPATH="${TOOLKIT}/lib:${PYTHONPATH:-}"
exec python3 -m goat.cli "$@"
LAUNCHER
chmod +x "$GOAT_BIN"

ok "Package created"
find "$TOOLKIT_DIR" -type f | sort | while read -r f; do
    printf "  %8d  %s\n" "$(wc -c <"$f" | tr -d ' ')" "${f#$TOOLKIT_DIR/}"
done

# ── 4. Install goat to PATH ───────────────────────────────────────────────────
if [[ $SKIP_INSTALL -eq 1 ]]; then
    section "Skipping installation (--skip-install)"
else
    section "Install goat to PATH"
    print "After installation you can run ${C_BOLD}goat${C_RESET} from anywhere (no leading ./).\n"
    print "  1) ~/.local/bin  (user install — no sudo needed)"
    print "  2) /usr/local/bin (system-wide — needs sudo)"
    print "  3) Both"
    print "  4) Skip\n"
    printf "Choice [1-4]: "
    read -r choice

    install_user() {
        mkdir -p "${HOME}/.local/bin"
        ln -sf "$GOAT_BIN" "${HOME}/.local/bin/goat"
        ok "Installed → ~/.local/bin/goat"
    }
    install_system() {
        if [[ $EUID -eq 0 ]]; then
            ln -sf "$GOAT_BIN" /usr/local/bin/goat
        else
            warn "/usr/local/bin requires sudo — you'll be prompted"
            sudo ln -sf "$GOAT_BIN" /usr/local/bin/goat
        fi
        ok "Installed → /usr/local/bin/goat"
    }

    case $choice in
        1) install_user ;;
        2) install_system ;;
        3) install_user; install_system ;;
        4) warn "Skipped — you can still run: ${GOAT_BIN}" ;;
        *) warn "Invalid choice — skipped" ;;
    esac

    # Ensure ~/.local/bin is on PATH for future shells
    if [[ -d "${HOME}/.local/bin" ]] \
       && [[ ":${PATH}:" != *":${HOME}/.local/bin:"* ]]; then
        warn "~/.local/bin is not on PATH"
        print "  Add this to your ~/.zshrc:\n"
        print "    export PATH=\"\${HOME}/.local/bin:\${PATH}\"\n"
    fi
fi

# ── 5. Summary ────────────────────────────────────────────────────────────────
section "Done — what you have"

print ""
print "  ${C_BOLD}Package:${C_RESET}        ${TOOLKIT_DIR}"
print ""
print "  ${C_BOLD}dr1zzle/${C_RESET}        A11 (T8015) payload for USB-based boot"
print "  ${C_BOLD}usbr34ker/${C_RESET}      A12/A12X/A13 RP2350 board firmware (.uf2)"
print "  ${C_BOLD}goat${C_RESET}            CLI tool (keygen, seal, push, kload, pwn)"
print ""
print "  ${C_BOLD}Quick start:${C_RESET}"
print ""
print "    goat --help                    show all commands"
print "    goat kload <image>             boot image on a DFU device"
print "    goat push <container>          push sealed container to goatloader"
print "    goat pwn                       exploit device → pwndfu"
print "    goat shell                     remote console over TCP"
print ""
print "  ${C_BOLD}usbr34ker:${C_RESET} flash a .uf2 onto an RP2350 board (Pico 2,"
print "    Pimoroni Tiny 2350, Waveshare RP2350), then connect board → device."
print ""
print "  ${C_YELLOW}Note:${C_RESET} dr1zzle targets A11, usbr34ker targets A12/A13."
print "    They are different exploits for different chips.\n"