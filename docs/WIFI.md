# Wi-Fi boundary

`drizzle/wifi.h` and `net/wifi.c` contain the portable part of the driver:

- lifecycle and association state (`down`, `ready`, `scanning`,
  `associating`, `associated`, `error`);
- a bounded scan-result representation;
- a link-layer adapter for the existing Ethernet/IP stack; and
- a fail-closed receive/transmit path.

`tests/wifi_test.c` exercises start, scan, association, frame transmit, frame
receive, disconnect, and reset with a fake SDIO backend. `make profiles-test`
builds the same implementation with the QEMU profile.

The A11 radio is now narrowed down from public device-tree evidence: the D22AP
(iPhone X) WLAN node identifies a Broadcom 4357 module (`herculese`) with
`wlan-pcie-uart,bcm4357`, a `function-reg_on` power function, a PCIe-port
control function, a `wifi-calibration-msf` property, and a board MAC address.
That identifies the transport family as Apple PCIe plus a UART/control path; it
does not provide the controller register map or a usable firmware image.

The old `src/research/wifi.c` register offsets were an unverified guess and are
intentionally not used by the portable driver. A real A11 backend still needs:

1. the Apple PCIe WLAN controller/register sequence, endpoint BAR/MSI setup,
   and DART/IOMMU mappings;
2. the `reg_on` GPIO/PMU sequence and UART/coexistence protocol;
3. the source and format of `wifi-calibration-msf`, the BCM4357 firmware
   package, and its validation/load protocol; and
4. an RX/TX interrupt or polling implementation that calls
   `drizzle_wifi_receive_frame()`.

The local `iphemeral-latest` emulator does contain a `WifiSdio` model and
synthetic MAC/firmware/ring/IRQ tests. Its own T8015 configuration labels the
`0x20a170000` window as synthetic harness space, explicitly **not A11 silicon**;
it does not contain the BCM4357 PCIe/UART protocol, firmware package,
calibration parser, or hardware capture needed by this driver.

See [WIFI_A11_FINDINGS.md](WIFI_A11_FINDINGS.md) for the evidence and the
explicit boundary between observed properties and work that remains
unverified.

QEMU `virt` has no emulated Wi-Fi device, so the fake backend test is the
strongest verification available in this repository. It proves the driver
contract and state machine, not radio association on an A11.
