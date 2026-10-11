# Goat / usbr34ker walkthrough

Dr1zzle's Goat keeps the Apple A11 `kload` path separate from the RP2350
helper-board path. The bundled UF2 images are flashed to a Pico 2 or one of
the supported Waveshare/Pimoroni boards, then Goat can attach to the board's
USB CDC UART at 115200 baud.

From the Dr1zzle checkout:

```sh
./goat/goat usbr34ker walkthrough
./goat/goat usbr34ker list
./goat/goat usbr34ker flash --board pico2
```

Hold BOOTSEL while connecting the board for the first flash. If the boot
volume is not auto-detected, pass `--mount /Volumes/RPI-RP2` (macOS) or the
mounted `RPI-RP2` path on Linux. The terminal uses 115200 8-N-1; press
Ctrl-] to exit.

After the helper board is running and its terminal is available, use
`./goat/goat pwn` for the separate Dr1zzle A11 DFU path.
Goat does not pass UF2 bytes to `kload`: UF2 is RP2350 firmware, while kload
accepts AArch64 ELF/bin images or signed `.g1` containers.
