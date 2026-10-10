# A11 Wi-Fi findings

This is the current clean-room hardware record for the A11 WLAN backend. It
records public observations only; it does not include proprietary firmware,
decrypted payloads, or guessed register writes.

## What PongoOS provides

PongoOS does not provide an A11 WLAN driver, radio-bus implementation, Broadcom
firmware loader, or calibration parser. Its public driver tree contains UART,
USB, GPIO, timer, SEP, AES, framebuffer, and platform support, but no Wi-Fi,
WLAN, SDIO, or PCIe radio driver. The Linux module directory likewise contains
only the small Linux support module, not a wireless stack.

Therefore PongoOS is useful as a source of general Apple platform primitives,
but it does not supply the missing BCM4357 transport contract.

## What is observable for the A11 target

The public D22AP (iPhone X) device-tree dump gives the following facts:

| Observation | Meaning | Status |
| --- | --- | --- |
| `wifi-chipset = 4357` | Broadcom BCM4357 family is the WLAN device | observed |
| `module-instance = herculese` | Board/module identity used by the WLAN node | observed |
| `compatible = wlan-pcie-uart,bcm4357` | Apple exposes a PCIe plus UART/control transport | observed; controller details absent |
| `function-reg_on` | Radio power-on is a board function, not a guessed MMIO bit | observed; sequence absent |
| `function-pcie_port_control` | PCIe WLAN port requires platform-specific setup | observed; arguments/implementation absent |
| `wifi-calibration-msf` | Calibration is supplied through a platform property | observed; payload and format absent |
| `local-mac-address` | Board MAC is supplied separately from the radio endpoint | observed |
| PCIe `wlan` endpoint, IOMMU/DART references | The endpoint is behind Apple PCIe and address translation | observed; BAR/MSI/DART programming absent |

The device-tree properties are not a firmware image, a register specification,
or a captured transaction trace. They are enough to stop treating SDIO as the
A11 default and to define the next interfaces, but not enough to safely turn on
the radio.

## What iPhemeral provides locally

The local `/Users/failbr34k/Downloads/iphemeral-latest` tree does contain
radio-related emulator code, but it is a synthetic SDIO model rather than an
A11 hardware trace:

- `crates/iphem-devices/src/user_peripherals.rs` implements `WifiSdio` as a
  256-byte CMD52/CMD53-style register window with synthetic MAC, Broadcom
  vendor/device IDs (`0x14e4`/`0x43a0`), firmware state/version fields, TX/RX
  rings, and an IRQ hook.
- `crates/iphem-soc/src/lib.rs` maps that model at `0x20a170000` for several
  SoC profiles. The T8015 (A11) entry explicitly labels the `0x20a…` band as
  **synthetic per-peripheral harness space, not A11 silicon**.
- `phase168`, `phase170`, `phase171`, `phase172`, and `phase174` exercise
  register round-trips, synthetic iBoot writes, and synthetic RX IRQ delivery.
  They do not capture a real radio transaction or load a real WLAN image.

The same tree has no `wlan-pcie-uart`, `BCM4357`, `BCM43572`, `herculese`, or
`wifi-calibration-msf` implementation, and no WLAN firmware/calibration parser
or captured A11 radio trace. Its Phase 157 radio work is a separate cellular
baseband/mailbox status stub.

The clean-room note in this repository records only high-level architectural
consultation of `iphemeral-latest`; no source, types, firmware, calibration
blob, or implementation text was imported.

## Remaining implementation inputs

The active driver must remain fail-closed until these inputs are obtained from
public documentation, hardware observation, or a legally usable reference:

1. Apple A11 PCIe controller base/register sequence and WLAN endpoint config;
2. MSI/interrupt routing and DART/IOMMU mappings for the WLAN endpoint;
3. `reg_on` power and reset ordering, including the UART/coexistence channel;
4. the BCM4357 firmware package and its load/validation protocol;
5. the `wifi-calibration-msf` payload source, schema, and MAC/NVRAM policy; and
6. a hardware or faithful radio emulator test that proves scan, association,
   RX, and TX.

Generic Linux `brcmfmac` firmware/NVRAM conventions are useful background, but
they must not be assumed to match Apple's BCM4357 PCIe/UART implementation.

## Public references

- [PongoOS driver tree](https://github.com/checkra1n/PongoOS/tree/master/src/drivers)
- [Apple Common Criteria report](https://www.commoncriteriaportal.org/files/epfiles/st_vid10851-st.pdf)
- [iPhone X D22AP device-tree dump](https://gist.github.com/freedomtan/1bbada7f19b7eb058e380e9d219ab268)
- [iPhone 8 Plus teardown](https://www.techinsights.com/blog/apple-iphone-8-plus-teardown)
- [Linux brcmfmac background](https://wireless.docs.kernel.org/en/latest/en/users/drivers/brcm80211.html)
