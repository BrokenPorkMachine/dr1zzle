#!/bin/sh
set -eu

qemu_bin=${QEMU:-qemu-system-aarch64}
image=${DR1ZZLE_ELF:-build/a11-payload.elf}
machine=${DR1ZZLE_QEMU_MACHINE:-virt}
cpu=${DR1ZZLE_QEMU_CPU:-cortex-a72}
memory=${DR1ZZLE_QEMU_MEMORY:-8G}
display=default
serial=mon:stdio
build=1

usage() {
    echo "usage: $0 [--headless] [--display] [--no-build]"
    echo "       QEMU=... DR1ZZLE_ELF=... DR1ZZLE_QEMU_MEMORY=... $0"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --headless|-n)
            display=none
            ;;
        --display|-d)
            display=default
            ;;
        --no-build)
            build=0
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [ "$build" -eq 1 ]; then
    make
fi

if [ ! -f "$image" ]; then
    echo "missing QEMU image: $image" >&2
    exit 1
fi

cat <<EOF
Launching dr1zzle/A11 payload in QEMU
  image:   $image
  machine: $machine
  cpu:     $cpu
  memory:  $memory
  uart:    $serial
  display: $display

Note: this payload is linked for Apple A11 SRAM/MMIO. QEMU's generic virt board
does not emulate S5L UART, USB PHY, DWC2, ACE2, or Apple memory-mapped devices.
If UART is silent, the image is running against missing hardware, not your
terminal being broken.
EOF

if [ "$display" = "none" ]; then
    exec "$qemu_bin" \
        -machine "$machine" \
        -cpu "$cpu" \
        -m "$memory" \
        -nographic \
        -serial "$serial" \
        -kernel "$image"
fi

exec "$qemu_bin" \
    -machine "$machine" \
    -cpu "$cpu" \
    -m "$memory" \
    -serial "$serial" \
    -display "$display" \
    -device ramfb \
    -kernel "$image"
