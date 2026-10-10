#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

qemu_bin=${QEMU:-qemu-system-aarch64}
display_backend=${DR1ZZLE_QEMU_DISPLAY:-cocoa}
mode=display
build=1

usage() {
    cat <<EOF
usage: $0 [--display | --headless] [--no-build]

  --display   show the monitor's framebuffer; UART stays in this terminal (default)
  --headless  run the small UART-only profile
  --no-build  use an existing profile image

Environment: QEMU=... DR1ZZLE_QEMU_DISPLAY=...
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --display|-d) mode=display ;;
        --headless|-n) mode=headless ;;
        --no-build) build=0 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done

if ! command -v "$qemu_bin" >/dev/null 2>&1; then
    echo "QEMU not found: $qemu_bin" >&2
    exit 1
fi

if [ "$mode" = display ]; then
    profile=monitor
else
    profile=small
fi
image="build/profiles/$profile/monitor.elf"

if [ "$build" -eq 1 ]; then
    make -f boards/Makefile "PROFILE=$profile"
fi
if [ ! -f "$image" ]; then
    echo "missing profile image: $image (run without --no-build)" >&2
    exit 1
fi

echo "Starting dr1zzle ($profile profile); UART is in this terminal. Press Ctrl-C to quit."
if [ "$mode" = headless ]; then
    exec "$qemu_bin" -machine virt -cpu cortex-a53 -m 128M \
        -display none -serial stdio -monitor none -kernel "$image"
fi

exec "$qemu_bin" -machine virt -cpu cortex-a53 -m 128M \
    -device ramfb -display "$display_backend" \
    -serial stdio -monitor none -kernel "$image"
