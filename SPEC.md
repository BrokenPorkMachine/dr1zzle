# A11 Research Payload — Technical Specification

**Version:** 1.0  
**Classification:** Private / Proprietary  
**Target:** Apple A11 (T8015) — iPhone 8 / iPhone X  
**Entry Point:** checkm8 (DFU) → Payload upload via DFU DNLOAD  
**Host Interface:** USB CDC-ECM (TCP over USB) + UART fallback  

---

## 1. Scope & Objectives

### 1.1 Purpose
A bare-metal research payload for Apple A11 SoC providing deterministic, cycle-accurate hardware access via TCP-over-USB console. Implements all drivers from register-level specifications — no third-party OS code.

### 1.2 Core Capabilities
| Category | Features |
|-----------|----------|
| **Memory** | SecureROM dump, NAND dump + APFS parse, iBoot dump (recovery), RAM peek/poke |
| **Crypto** | AES/GID/UID engine, KBAG decryption (GID-wrapped keys), keybag parsing |
| **Peripherals** | PMGR clocks/power, GPIO/I2C/SPI/AP GPIO, ACE2/ACE3 USB host controller |
| **SEP** | ASC mailbox protocol (opcodes 0x05/0x06/0x10/0x11/0xFF), SEPOS interaction |
| **Kernel** | Custom kernel boot (`bootx`), iOS RAM patching (kpatch/kcall), panic log parse |
| **Console** | TCP over USB CDC-ECM (primary), UART 115200 (fallback), command history |
| **Determinism** | Cycle-accurate timing API, µs-precision delays, IRQ latency measurement |

### 1.3 Non-Goals
- WiFi/BT drivers (stubbed for future)
- SEPOS exploit/dump (no public A11 SEP vuln)
- iOS userspace interaction (kernel-only)
- Graphical output (headless)

---

## 2. Hardware Platform

### 2.1 Target SoC
| Parameter | Value |
|-----------|-------|
| **SoC** | T8015 (A11 Bionic) |
| **CPU** | 2× Monsoon (perf) + 4× Mistral (eff) — ARMv8.3-A |
| **RAM** | LPDDR4X — 2/3 GB (payload runs in SRAM) |
| **SRAM** | 0x1800_00000 — 0x1801_E8000 (1.9 MB) |
| **SecureROM** | 0x1000_00000 — 0x1010_0000 (1 MB) |
| **NAND** | NVMe-like controller at 0x2000_00000 |
| **USB** | DWC2 OTG (device) + ACE2 (host) |
| **SEP** | ARMv7-A (S5L8960X) — separate CPU |

### 2.2 Memory Map (from iphem-soc)
```c
#define SRAM_BASE           0x180000000ULL
#define SRAM_SIZE           0x1E8000ULL

#define SECURE_ROM_BASE     0x100000000ULL
#define SECURE_ROM_SIZE     0x100000ULL

#define UART_BASE           0x20A0C0000ULL
#define TIMER_BASE          0x20E100000ULL
#define AIC_BASE            0x232100000ULL
#define PMGR_BASE           0x232000000ULL
#define MAILBOX_BASE        0x23C000000ULL
#define DCP_BASE            0x235000000ULL
#define NOR_BASE            0x240000000ULL
#define BLOCK_BASE          0x241000000ULL
#define NAND_BASE           0x200000000ULL
#define USB_BASE            0x250000000ULL
#define WATCHDOG_BASE       0x2352B0000ULL
#define GPIO_BASE           0x20A100000ULL
#define I2C_BASE            0x20A200000ULL
#define SPI_BASE            0x20A400000ULL
#define PMU_BASE            0x20A000000ULL
#define SPMI_BASE           0x20A300000ULL
#define THERMAL_BASE        0x20A700000ULL
#define USB_PHY_BASE        0x20A1A0000ULL
#define USB_MUX_BASE        0x20A1A1000ULL
#define USB_PD_BASE         0x20A1A2000ULL
#define PANEL_BASE          0x20A110000ULL
#define DSI_PHY_BASE        0x20A120000ULL
#define RASTER_BASE         0x20A130000ULL
#define TOUCH_BASE          0x20A140000ULL
#define AUDIO_BASE          0x20A150000ULL
#define BT_BASE             0x20A160000ULL
#define WIFI_BASE           0x20A170000ULL
#define CAMERA_BASE         0x20A180000ULL
#define SENSORHUB_BASE      0x20A190000ULL
#define ACE2_BASE           0x230000000ULL
#define ACE2_SIZE           0x10000ULL
```

---

## 3. Boot Flow

### 3.1 Entry Conditions (from checkm8)
```
Register State at _start:
  x0 = DTB pointer (0 if none)
  x1 = 0
  x2 = 0
  x3 = 0
  EL = EL1h
  MMU = Off
  Caches = Off
  VBAR_EL1 = 0
```

### 3.2 Initialization Sequence
```
1. Disable MMU, caches, alignment check (SCTLR_EL1)
2. Install VBAR_EL1 → vector table
3. Enable CNTPCT_EL0 (physical timer @ 24 MHz)
4. Build page tables (identity map + device regions)
5. Initialize UART0 (PL011/S5L @ 115200 8N1)
6. Initialize USB PHY + DWC2 device mode
7. Enable MMU + caches (SCTLR_EL1.M=1, C=1, I=1)
8. Enable IRQ/FIQ (DAIF)
9. Initialize all drivers (PMGR, GPIO, I2C, SPI, NAND, AES, ACE2, SEP)
10. Start CDC-ECM TCP server
11. Enter shell loop
```

### 3.3 Vector Table (64 bytes @ 0x1800_00000)
| Offset | Exception | Handler |
|--------|-----------|---------|
| 0x000 | Synchronous (EL1h) | `sync_el1h` |
| 0x080 | IRQ (EL1h) | `irq_el1h` |
| 0x100 | FIQ (EL1h) | `fiq_el1h` |
| 0x180 | SError (EL1h) | `serror_el1h` |
| 0x200–0x3FF | Lower EL / AArch32 | `unhandled` |

---

## 4. Driver Specifications

### 4.1 UART (PL011 / S5L) — `drivers/uart.c`
| Register | Offset | Use |
|----------|--------|-----|
| ULCON | 0x00 | Line control (8N1 = 0x3) |
| UCON | 0x04 | Control (Rx/Tx enable = 0x5) |
| UFCON | 0x08 | FIFO control (enable = 0x3) |
| UMCON | 0x0C | Modem control (0) |
| UTRSTAT | 0x18 | Tx/Rx status |
| UTXH | 0x20 | Tx FIFO |
| URXH | 0x24 | Rx FIFO |
| UBRDIV | 0x28 | Baud divisor (PCLK=24MHz) |

**API:**
```c
void uart_early_init(void)          // 115200 default
void uart_putc(char c)              // Blocking TX
int uart_getc(void)                 // Non-blocking RX
void uart_puts(const char *s)       // String output
```

### 4.2 Timer (CNTPCT_EL0) — `drivers/timer.c`
| Register | Access | Frequency |
|----------|--------|-----------|
| CNTPCT_EL0 | Read | 24 MHz (fixed) |
| CNTP_CTL_EL0 | RW | Enable/IMASK |
| CNTP_TVAL_EL0 | RW | Timer value |
| CNTP_CVAL_EL0 | RW | Compare value |

**API:**
```c
void timer_init(void)                      // Enable counter
uint64_t timer_now_cycles(void)            // Raw cycles
uint64_t timer_now_us(void)                // Microseconds since boot
uint64_t timer_now_ms(void)                // Milliseconds since boot
void timer_sleep_us(uint64_t us)           // Busy-wait µs
void timer_sleep_ms(uint64_t ms)           // Busy-wait ms
```

### 4.3 USB PHY — `drivers/usb.c`
| Step | Register | Value | Timing |
|------|----------|-------|--------|
| 1 | GUSBCFG.PHY_RESET | 1 | — |
| 2 | — | wait | 1 ms |
| 3 | GUSBCFG.PHY_RESET | 0 | — |
| 3 | GRSTCTL.AHBIDLE | poll | ≤ 10 ms |

### 4.4 DWC2 Device Core — `drivers/usb.c`
| Register | Init Value | Purpose |
|----------|------------|---------|
| GRSTCTL | CSRST=1 → 0 | Soft reset |
| GAHBCFG | GLBL_INTR_EN \| HBSTLEN_INCR16 | AHB config |
| GUSBCFG | PHY_UTMI \| TOUTCAL(7) \| USBTRDTIM(5) \| PHY_IF_16BIT | PHY config |
| DCFG | DESCDMA \| DEVSPD_HS | Device config |
| DCTL | SGINAK \| CGINAK | Clear NAKs |
| GINTMSK | USBRST \| ENUMDNE \| RXFLVL \| IEPINT \| OEPINT | Interrupts |

**Endpoint 0 (Control):**
- DOEPCTL0: EPENA=1, CNAK=1, MPS=64, USB_ACTEP=1
- DIEPCTL0: EPENA=1, CNAK=1, MPS=64, USB_ACTEP=1

### 4.5 CDC-ECM — `drivers/usb.c` (stub)
**Endpoints:**
| EP | Dir | Type | MaxPacket | Use |
|----|-----|------|-----------|-----|
| 0 | OUT/IN | Control | 64 | Standard + CDC requests |
| 1 | IN | Interrupt | 16 | Network notifications |
| 2 | OUT | Bulk | 512 | RX Ethernet frames |
| 2 | IN | Bulk | 512 | TX Ethernet frames |

### 4.6 NAND Controller — `drivers/nand.c` (planned)
**Registers (from pongoOS + xnu):**
| Register | Offset | Use |
|----------|--------|-----|
| NFC_CTRL | 0x00 | Reset, enable, ECC |
| NFC_STATUS | 0x04 | Ready/busy, ECC status |
| NFC_CMD | 0x08 | Command (0x00/0x30/0x90/0x60) |
| NFC_ADDR | 0x0C | Address cycles |
| NFC_DATA | 0x10 | Data FIFO |
| NFC_ECC_CTRL | 0x14 | BCH config |
| NFC_ECC_STATUS | 0x18 | Error count/position |

### 4.7 AES Engine — `drivers/aes.c` (planned)
**Registers:**
| Register | Offset | Use |
|----------|--------|-----|
| AES_CTRL | 0x00 | START, DIR, MODE, KEY_SEL |
| AES_STATUS | 0x04 | BUSY, ERROR |
| AES_KEY_SEL | 0x08 | GID/UID/PASSCODE slot |
| AES_IV | 0x10-0x2C | 16-byte IV |
| AES_FIFO_IN | 0x30 | Input FIFO (4×32-bit) |
| AES_FIFO_OUT | 0x34 | Output FIFO (4×32-bit) |

**AES_CTRL bits:**
| Bit | Name | Value |
|-----|------|-------|
| 0 | START | 1 = start |
| 1 | DIR | 0=enc, 1=dec |
| 2 | MODE | 0=AES128, 1=AES256 |
| 4:5 | KEY_SEL | 0=GID, 1=UID, 2=GID+UID, 3=Passcode |

### 4.7 PMGR — `drivers/pmgr.c` (planned)
**Registers:**
| Register | Offset | Use |
|----------|--------|-----|
| PS_REQ | 0x00 | Power state request |
| PS_ACK | 0x08 | Power state ack |
| CLK_EN | 0x10 | Clock enable |
| CLK_DIS | 0x18 | Clock disable |
| RESET_CTRL | 0x20 | Reset control |

### 4.8 ACE2/ACE3 USB Host — `drivers/ace2.c` (planned)
**Register Map (DWC2 Host Mode + Apple Extensions):**
| Register | Offset | Use |
|----------|--------|-----|
| CAPLENGTH | 0x00 | Capability length |
| HCSPARAMS | 0x04 | Structural params |
| HCCPARAMS | 0x08 | Capability params |
| USBCMD | 0x10 | Command |
| USBSTS | 0x14 | Status |
| USBINTR | 0x18 | Interrupt enable |
| PORTSC | 0x44 | Port status/control (×N) |

---

## 5. Research Modules

### 5.1 SecureROM Dumper — `research/secure_rom.c` (planned)
```c
void dump_secure_rom(void) {
    // Map SECURE_ROM_BASE (0x1000_00000) in page tables (RO)
    // Verify signature (0x1000_00000 = 0x9000_0000? adrp)
    // Stream 1 MB via TCP (16 KB chunks)
    // Verify SHA-256 against known hash
}
```

### 5.2 NAND Dumper + APFS — `research/nand_dump.c` (planned)
```c
void dump_nand_all(void) { /* Scan all blocks, read all pages */ }
void extract_apfs_files(const char **paths) { /* Parse APFS → extract files */ }
```

### 5.3 iBoot Dumper — `research/iboot_dump.c` (planned)
```c
void dump_iboot_via_recovery(void) {
    // 1. Upload iBSS → iBEC → recovery mode
    // 2. Boot custom recovery ramdisk with iBoot dumper
    // 3. Dumper runs in iBoot context, dumps itself
    // 4. Stream via TCP
}
```

### 5.4 KBAG Decryptor — `research/keybag.c` (planned)
```c
void decrypt_keybag(const uint8_t *img4) {
    // 1. Parse IMG4 → extract KBAG (element 4)
    // 2. Parse KBAG: SEQUENCE { SEQUENCE { wrap_type, iv, wrapped_key } }
    // 3. For each key with wrap_type == 0 (GID): aes.decrypt_gid(wrapped_key, iv)
    // 4. Return [(class, key_bytes)]
}
```

### 5.5 iOS Kernel Patcher — `research/kernel_patch.c` (planned)
```c
void patch_kernel_ram(uint64_t kernel_base, const Patch *patches) {
    // 1. Locate kernel in RAM (0x8000_0000_0 + slide)
    // 2. For each patch: verify original bytes → write new bytes
    // 3. Flush I-cache (IC IVAU) for modified pages
}
```

### 5.6 Panic Log Parser — `research/panic_log.c` (planned)
```c
void parse_panic_log(uint64_t ram_base) {
    // 1. Locate panic header (magic: "panic" or "core")
    // 2. Parse: registers, backtrace, memory map, log
    // 3. Symbolicate if kernel symbols available
}
```

---

## 6. Shell & Console

### 6.1 UART Shell — `shell/shell.c`
```
research> help
Available commands:
  memdump <addr> <len>     - Hex dump memory
  memwrite <addr> <hex>    - Write memory
  time                     - Show uptime
  reboot                   - Reboot to DFU
  help                     - This list
```

### 6.2 TCP Shell — `shell/tcp.rs` (planned)
**Protocol:** Line-based over TCP port 23 (telnet) or 2323 (binary)

---

## 7. Memory Layout (SRAM)

```
0x1800_00000  ┌─────────────────────┐
              │ Vector Table (768 B) │
0x1800_00300  ├─────────────────────┤
              │ .text (code)        │
              │ .rodata             │
              ├─────────────────────┤
              │ .bss                │
              ├─────────────────────┤
              │ .text (continued)   │
              ├─────────────────────┤
              │ .heap (64 KB)       │
              ├─────────────────────┤
              │ .stack (16 KB)      │
0x1801_E8000  └─────────────────────┘
```

---

## 8. Host Tool Specification

### 8.1 `a11-host` (Rust)
```bash
a11-host [OPTIONS] <COMMAND>

OPTIONS:
  -t, --transport <TYPE>    tcp|uart (default: tcp)
  -a, --address <IP>        Target IP (default: 192.168.42.1)
  -p, --port <PORT>         TCP port (default: 23)
  -d, --device <PATH>       UART device (default: /dev/tty.usbmodem*)

COMMANDS:
    shell              Interactive shell
    exec <cmd>         Single command
    upload <file>      Upload binary via DFU
    download <remote> <local>  Download file
    memdump <addr> <len> [out]  Memory dump
    nand dump [out]    Full NAND dump
    keybag <img4>      Decrypt KBAG
    reboot             Reboot to DFU
```

### 8.2 Deployment
```bash
# 1. Build payload
cargo build --release --target aarch64-unknown-none  # (from a11-payload)

# 2. Deploy via checkm8
ipwndfu -p              # checkm8
ipwndfu -l payload.bin  # upload payload

# 3. Connect via TCP
a11-host connect        # or telnet 192.168.42.1 23
```

---

## 9. Testing & Validation

### 9.1 Unit Tests (Host-side)
| Module | Tests |
|--------|-------|
| MMU | Identity map, device regions, permissions |
| UART | Loopback, baud rates, FIFO |
| Timer | µs accuracy, deadline, sleep |
| USB PHY | Reset sequence, calibration |
| DWC2 | EP0 control, bulk endpoints |
| CDC-ECM | Ethernet frames, ARP/ICMP/TCP |
| NAND | Read ID, read page, ECC |
| AES | GID decrypt, known vectors |
| PMGR | Device states, clocks |
| SEP | Mailbox round-trip |

### 9.2 Integration Tests (On Device)
| Test | Criteria |
|------|----------|
| `memdump 0x100000000 64` | Matches known SecureROM header |
| `nand dumpall` | All blocks read, ECC correct |
| `ace2 dump` | Registers match DWC2 + Apple ext |
| `aes test` | GID decrypt matches known keybag |
| `sepos ping` | Returns PONG in <10 ms |
| `pmgr get 0x20` | Returns 1 (USB always on) |
| `bootx pongoOS.bin` | Boots to pongo shell |

---

## 10. Deliverables

| Artifact | Format | Location |
|----------|--------|----------|
| Payload binary | `payload.bin` | `build/a11-payload.bin` |
| Payload ELF | `payload.elf` | `build/a11-payload.elf` |
| Host tool | `a11-host` | `target/release/a11-host` |
| Symbol map | `payload.map` | `build/a11-payload.map` |
| Build log | `build.log` | CI artifact |
| Test report | `test-results.xml` | CI artifact |

---

## 11. References (Internal)

| Document | Path |
|----------|------|
| A11 Memory Map | `include/memory_map.h` |
| UART Driver | `drivers/uart.c` |
| PMGR Driver | `drivers/pmgr.c` (planned) |
| NAND Driver | `drivers/nand.c` (planned) |
| AES Driver | `drivers/aes.c` (planned) |
| DWC2 Registers | `drivers/usb.c` |
| SEP Mailbox | `drivers/sep.c` (planned) |
| APFS Reader | `fs/apfs.c` (planned) |
| Page Tables | `arch/arm64/mmu.c` |

---

## 12. References (External — For Register Values Only)

| Source | Use |
|--------|-----|
| pongoOS `usbd.c` | USB init sequence, register write order |
| pongoOS `nand.c` | NAND command sequence, ECC |
| pongoOS `aes.c` | GID decrypt flow |
| pongoOS `sep.c` | Mailbox protocol, opcodes |
| pongoOS `console.c` | Shell structure, history |
| Linux `dwc2` driver | Host register map, PHY tuning |
| Linux `mtd/nand` | BCH implementation |
| xnu `IOKit/usb` | CDC-ECM descriptors |
| Apple `IMG4` spec | KBAG format |
| ARM DDI 0487 | ARMv8-A architecture |
