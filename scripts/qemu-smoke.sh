#!/bin/sh
set -eu

timeout_seconds=18
mode=smoke
qemu_bin=${QEMU:-qemu-system-aarch64}
image=${DR1ZZLE_IMAGE:-build/a11-payload.elf}
log_file=${DR1ZZLE_QEMU_LOG:-build/qemu-smoke.log}

usage() {
    echo "usage: $0 [--interactive] [--timeout seconds]"
    echo "       QEMU=... DR1ZZLE_IMAGE=... DR1ZZLE_QEMU_LOG=... $0"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --interactive|-i) mode=interactive ;;
        --timeout)
            shift
            if [ $# -eq 0 ]; then usage >&2; exit 2; fi
            timeout_seconds=$1
            ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done

make

if [ "$mode" = "interactive" ]; then
    exec "$qemu_bin" -machine virt -cpu cortex-a72 -m 8G -nographic -kernel "$image"
fi

mkdir -p "$(dirname "$log_file")"
rm -f "$log_file"

(
    sleep 1
    printf 'help\r'
    sleep 1
    printf 'info\r'
    sleep 1
    printf 'heap\r'
    sleep 1
    printf 'net\r'
    sleep 1
    printf 'time\r'
    sleep 1
    printf 'd\r'
    sleep 1
    printf 'c\r'
    sleep 1
    printf 's\r'
    sleep 1
    printf 'z\r'
    sleep 1
    printf 's\r'
    sleep 1
    printf 'q\r'
    sleep 1
    printf 'x\r'
    sleep 1
    printf '21 01 0000 0000 0000\r'
    sleep 1
) | "$qemu_bin" -machine virt -cpu cortex-a72 -m 8G -nographic -kernel "$image" >"$log_file" 2>&1 &

qemu_pid=$!
elapsed=0
while kill -0 "$qemu_pid" 2>/dev/null && [ "$elapsed" -lt "$timeout_seconds" ]; do
    sleep 1
    elapsed=$((elapsed + 1))
done

if kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
fi

if grep -F "unable to find CPU model" "$log_file" >/dev/null 2>&1; then
    echo "QEMU CPU model was rejected" >&2
    echo "log: $log_file" >&2
    exit 1
fi

if grep -F "Could not open" "$log_file" >/dev/null 2>&1; then
    echo "QEMU failed to open an emulated device or image" >&2
    echo "log: $log_file" >&2
    exit 1
fi

echo "qemu smoke passed: $log_file"
