# A11 Research Payload — Implementation Plan

**Version:** 1.0  
**Duration:** 12 weeks (3 months)  
**Team:** 1 engineer (solo)  
**Methodology:** Incremental bring-up — each phase boots further

---

## Phase Overview

| Phase | Duration | Focus | Boot Progress |
|-------|----------|-------|---------------|
| **0** | 1 week | Toolchain, build system, linker | — |
| **1** | 1 week | Startup, MMU, UART, Timer | UART "Hello" |
| **2** | 2 weeks | USB PHY → DWC2 → CDC-ECM → TCP | TCP shell |
| **3** | 2 weeks | Core drivers (PMGR, GPIO, I2C, SPI, Watchdog) | Hardware access |
| **4** | 2 weeks | NAND + APFS + AES/GID | Storage + Crypto |
| **5** | 1 week | ACE2 dump + SEP mailbox | Peripheral dump |
| **6** | 1 week | Research modules (KBAG, iBoot, kernel patch, panic) | Full feature set |
| **7** | 1 week | Shell polish, host tool, testing, CI | Production ready |

---

## Phase 0: Foundation (Week 1) ✅ COMPLETE

### Deliverables ✅
- [x] Rust toolchain + `aarch64-unknown-none` target
- [x] `Cargo.toml` with `no_std`, allocator, panic handler
- [x] `linker.ld` with SRAM layout (vectors, text, data, bss, heap, stack, page tables)
- [x] `build.rs` for objcopy + binary output
- [x] CI pipeline (GitHub Actions): build → objcopy → artifact

### Tasks ✅
| Task | File | Status |
|------|------|--------|
| Initialize Cargo workspace (payload + host-tool) | `Cargo.toml` | ✅ |
| Linker script with SRAM regions | `linker/a11.ld` | ✅ |
| Vector table assembly (64 bytes) | `src/arch/arm64/start.S` | ✅ |
| MMU init stub (identity map) | `src/arch/arm64/mmu.c` | ✅ |
| Panic handler → UART | `src/drivers/uart.c` | ✅ |
| Heap allocator (linked-list) | `src/util.c` | ✅ |
| CI: build + objcopy → `payload.bin` | `scripts/build.sh` | ✅ |

### Acceptance Criteria ✅
```bash
cargo build --release --target aarch64-unknown-none
# Produces payload.bin (≤ 500 KB)
# Boots to UART "Hello" on hardware
```

---

## Phase 1: Bring-Up (Week 1) ✅ COMPLETE

### Deliverables ✅
- [x] MMU with identity map + device regions (from iphem-soc)
- [x] UART driver (PL011/S5L) at 115200 8N1
- [x] Timer driver (CNTPCT_EL0 @ 24 MHz)
- [x] Exception handlers (sync/IRQ/FIQ/SError)
- [x] UART shell prompt: `research>`

### Tasks ✅
| Task | File | Reference |
|------|------|-----------|
| Page table setup (L0/L1/L2/L3) | `src/arch/arm64/mmu.c` | ✅ |
| Identity map SRAM (RW, cacheable) | `mmu.c` | ✅ |
| Map device regions (RO, XN, PXN, Device-nGnRnE) | `mmu.c` | ✅ |
| UART init (PL011/S5L registers) | `src/drivers/uart.c` | ✅ |
| Timer init (CNTPCT_EL0 enable) | `src/drivers/timer.c` | ✅ |
| Exception vectors + handlers | `src/arch/arm64/exception.c` | ✅ |
| `c_main()` → UART shell loop | `src/main.c` | ✅ |

### Acceptance Criteria ✅
```
Device in DFU → ipwndfu -l payload.bin
→ UART: "=== A11 Research Payload ==="
→ UART: "research> "
→ Type "help" → command list
→ memdump 0x100000000 64 → SecureROM header
```

---

## Phase 2: USB + TCP Stack (Weeks 2-3) 🔄 IN PROGRESS

### Deliverables
- [x] USB PHY init + calibration
- [x] DWC2 device core init
- [ ] CDC-ECM device (EP0 + EP1 IN + EP2 IN/OUT)
- [ ] Minimal TCP stack (ARP/ICMP/IPv4/TCP)
- [ ] Telnet server on port 23
- [ ] TCP shell identical to UART shell

### Tasks
| Task | File | Reference | Status |
|------|------|-----------|--------|
| PHY reset + calibration sequence | `src/drivers/usb.c` | pongoOS usb_phy_init | 🔄 |
| DWC2 core init (GRSTCTL → DCFG) | `src/drivers/usb.c` | pongoOS usbd_init | 🔄 |
| EP0 control transfers (standard + CDC) | `src/drivers/usb.c` | pongoOS usbd_ep0 | 🔄 |
| CDC-ECM descriptors | `src/drivers/usb.c` | pongoOS usbd_cdc_ecm | 🔄 |
| EP1 IN (interrupt) + EP2 IN/OUT (bulk) | `src/drivers/usb.c` | pongoOS | 🔄 |
| Ethernet frame RX/TX rings | `src/drivers/usb.c` | — | 🔄 |
| ARP/ICMPv4/IPv4 parsing | `src/shell/tcp.c` | lwIP raw API | 🔄 |
| TCP state machine (LISTEN→ESTABLISHED) | `src/shell/tcp.c` | lwIP raw API | 🔄 |
| Telnet server (port 23) | `src/shell/tcp.c` | — | 🔄 |
| Shell abstraction (UART + TCP unified) | `src/shell/console.c` | — | 🔄 |

### Acceptance Criteria
```
Device boots → enumerates as CDC-ECM (usb0/enX)
Host: telnet 192.168.42.1 23
→ "research> " prompt over TCP
→ All UART commands work over TCP
→ ping 192.168.42.1 works
→ TCP shell survives 100 commands without disconnect
```

---

## Phase 3: Core Peripheral Drivers (Weeks 4-5) ⏳ PENDING

### Deliverables
- [ ] PMGR (device states, clocks, resets)
- [ ] GPIO (read/write/function select)
- [ ] I2C master (scan/read/write)
- [ ] SPI master (transfer)
- [ ] Watchdog (arm/kick/disable)
- [ ] All accessible via shell commands

### Tasks
| Task | File | Reference | Status |
|------|------|-----------|--------|
| PMGR register map + device lookup | `src/drivers/pmgr.c` | iphem-devices PmgrPowerState | ⏳ |
| PMGR get/set device state | `pmgr.c` | iphem-soc PMGR_BASE | ⏳ |
| PMGR clock enable/disable | `pmgr.c` | — | ⏳ |
| GPIO function select + read/write | `src/drivers/gpio.c` | iphem-devices AppleGpio | ⏳ |
| I2C master (polling) | `src/drivers/i2c.c` | iphem-devices I2c | ⏳ |
| I2C bus scan command | `src/shell/shell.c` | — | ⏳ |
| SPI master (polling) | `src/drivers/spi.c` | iphem-devices Spi | ⏳ |
| Watchdog init/kick/disable | `src/drivers/watchdog.c` | iphem-devices Watchdog | ⏳ |
| Shell commands for all above | `src/shell/shell.c` | — | ⏳ |

### Acceptance Criteria
```
research> pmgr get 0x20 → 1 (USB on)
research> gpio read 42 → 0/1
research> i2c scan → [0x48, 0x68, ...]
research> spi xfer 0x9F → [0xEF, 0x40, 0x18] (flash ID)
research> watchdog arm 5 → reboots in 5s if not kicked
```

---

## Phase 4: Storage + Crypto (Weeks 6-7) ⏳ PENDING

### Deliverables
- [ ] NAND controller (read ID, read page, ECC)
- [ ] APFS reader (container → volume → file)
- [ ] AES engine (GID decrypt, KBAG parse)
- [ ] Full NAND dump + APFS file extraction

### Tasks
| Task | File | Reference | Status |
|------|------|-----------|--------|
| NAND controller init + ID read | `src/drivers/nand.c` | pongoOS nand.c | ⏳ |
| NAND read page (column + row addr) | `nand.c` | pongoOS nand_read_page | ⏳ |
| BCH-8 ECC correction | `nand.c` | Linux mtd/nand | ⏳ |
| Bad block scanning | `nand.c` | — | ⏳ |
| APFS container locate (NXSB) | `src/fs/apfs.c` | iphem-devices apfs.rs | ⏳ |
| APFS checkpoint → superblock → volume | `apfs.c` | iphem-devices | ⏳ |
| B-tree traversal → file read | `apfs.c` | iphem-devices | ⏳ |
| AES engine (GID decrypt flow) | `src/drivers/aes.c` | pongoOS aes.c | ⏳ |
| KBAG parse (IMG4 element 4) | `src/research/keybag.c` | IMG4 spec | ⏳ |
| KBAG decrypt (GID-wrapped keys) | `keybag.c` | pongoOS aes.c | ⏳ |
| Shell commands: nand, apfs, aes, keybag | `shell.c` | — | ⏳ |

### Acceptance Criteria
```
research> nand dumpall → streams 128 MB via TCP (ECC OK)
research> apfs extract /kernelcache → 50 MB kernelcache.bin
research> aes test → GID decrypt matches known vector
research> keybag kernelcache.img4 → [class: 0x1, key: 32 bytes]
```

---

## Phase 5: ACE2 + SEP (Week 8) ⏳ PENDING

### Deliverables
- [ ] ACE2/ACE3 register dump (all 100+ regs)
- [ ] SEP mailbox client (opcodes 0x05/0x06/0x10/0x11/0xFF)
- [ ] SEP command shell integration

### Tasks
| Task | File | Reference | Status |
|------|------|-----------|--------|
| ACE2 register map (DWC2 host + Apple) | `src/drivers/ace2.c` | DWC2 host + Apple ext | ⏳ |
| ACE2 dump all registers command | `ace2.c` | — | ⏳ |
| SEP mailbox register map | `src/drivers/sep.c` | AppleAscMailbox | ⏳ |
| SEP send_command(opcode, data) | `sep.c` | pongoOS sep.c | ⏳ |
| SEP opcodes: ping, get_random, boot_tz0 | `sep.c` | pongoOS sep.c | ⏳ |
| Shell: ace2 dump, sepos <cmd> | `src/shell/shell.c` | — | ⏳ |

### Acceptance Criteria
```
research> ace2 dump → 100+ registers (CAPLENGTH, PORTSC, etc.)
research> sepos ping → PONG (<10 ms)
research> sepos get_random → 32 random bytes
research> sepos boot_tz0 <sepOS> → ACK/NAK
```

---

## Phase 6: Research Modules (Week 9) ⏳ PENDING

### Deliverables
- [ ] KBAG decryptor (full IMG4 → decrypted keys)
- [ ] iBoot dumper (via recovery boot)
- [ ] Kernel RAM patcher (kpatch/kcall)
- [ ] Panic log parser

### Tasks
| Task | File | Reference | Status |
|------|------|-----------|--------|
| IMG4 parse → KBAG extract | `src/research/keybag.c` | IMG4 spec | ⏳ |
| KBAG parse → GID decrypt → keys | `keybag.c` | IMG4 + AES | ⏳ |
| iBoot dump via recovery boot | `src/research/iboot_dump.c` | pongoOS bootx | ⏳ |
| Kernel patcher (kpatch/kcall) | `src/research/kernel_patch.c` | pongoOS kpatch | ⏳ |
| I-cache flush (IC IVAU) | `kernel_patch.c` | ARM arch | ⏳ |
| Panic log locate + parse | `src/research/panic_log.c` | xnu panic format | ⏳ |
| Shell commands for all | `shell.c` | — | ⏳ |

### Acceptance Criteria
```
research> keybag kernelcache.img4 → decrypted AES keys
research> iboot dump → 2 MB iBoot.bin (verified SHA)
research> patch 0x80001000 orig=new → kernel patched + icache flush
research> panic → parsed registers + backtrace
```

---

## Phase 7: Polish, Host Tool, CI (Week 10) ⏳ PENDING

### Deliverables
- [ ] Host tool (`a11-host`) with all subcommands
- [ ] Full test suite (unit + integration)
- [ ] CI pipeline (build → test → artifact)
- [ ] Documentation (README, command reference)

### Tasks
| Task | File | Reference | Status |
|------|------|-----------|--------|
| Host tool: shell, exec, upload, download | `a11-host/src/main.rs` | — | ⏳ |
| Host tool: memdump, nand, keybag, reboot | `a11-host/src/commands.rs` | — | ⏳ |
| Unit tests (all drivers) | `*_test.c` | — | ⏳ |
| Integration test script | `tests/integration.sh` | — | ⏳ |
| CI: build → test → upload artifacts | `.github/workflows/ci.yml` | — | ⏳ |
| README + command reference | `README.md` | — | ⏳ |
| Build script (build + deploy) | `scripts/deploy.sh` | — | ⏳ |

### Acceptance Criteria
```
cargo test --all → 100% pass
a11-host shell → interactive TCP shell
a11-host memdump 0x100000000 256 → file.bin
a11-host nand dump nand.bin → 128 MB file
a11-host keybag kernelcache.img4 → keys.json
CI: push → build → test → artifacts uploaded
```

---

## Dependency Graph

```
Phase 0
    ↓
Phase 1 (MMU, UART, Timer, Shell)
    ↓
Phase 2 (USB → CDC-ECM → TCP)
    ↓
Phase 3 (PMGR, GPIO, I2C, SPI, WDT) ← can parallelize
    ↓
Phase 4 (NAND → APFS, AES → KBAG) ← depends on PMGR (NAND power)
    ↓
Phase 5 (ACE2, SEP) ← depends on PMGR (USB host power), USB (mailbox)
    ↓
Phase 6 (Research modules) ← depends on NAND, AES, TCP
    ↓
Phase 7 (Host tool, CI, Docs) ← depends on all
```

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| USB CDC-ECM enumeration fails | High | Blocks TCP | Fallback: UART-only shell; debug via UART logs |
| NAND ECC implementation bugs | High | Data corruption | Test with known-good NAND dump first |
| AES GID key not accessible | Medium | KBAG decrypt fails | Verify AES_KEY_SEL=0 works on A11 |
| TCP stack bugs (retransmit, window) | Medium | Unreliable shell | Start with stop-and-wait; add window later |
| SEP mailbox protocol mismatch | Low | SEP commands fail | Test ping/pong first; log all traffic |
| SRAM overflow (payload too large) | Low | Boot crash | Monitor `.bss` + heap; strip debug symbols |

---

## Milestone Gates

| Gate | Criteria | Go/No-Go |
|------|----------|----------|
| **M1: UART Shell** | `memdump 0x100000000 64` works | ✅ → Phase 2 |
| **M2: TCP Shell** | `telnet` + `ping` + 100 cmds | 🔄 → Phase 3 |
| **M3: Hardware Access** | `pmgr`, `gpio`, `i2c`, `spi` work | ⏳ → Phase 4 |
| **M4: Storage + Crypto** | NAND dump + AES GID decrypt | ⏳ → Phase 5 |
| **M5: Peripheral Dump** | ACE2 + SEP ping | ⏳ → Phase 6 |
| **M7: Ship** | All commands + CI green | ⏳ → Ship |

---

## Resource Requirements

| Resource | Specification |
|----------|---------------|
| **Hardware** | iPhone 8/X (A11) in DFU, USB-A host port (Pico/Mac/Linux) |
| **Software** | Rust 1.75+, `aarch64-unknown-none`, `ipwndfu`, `telnet` |
| **Reference Code** | iphemeral repo (local), pongoOS (GitHub, read-only) |
| **Documentation** | ARM DDI 0487, DWC2 spec, xnu source (register values only) |

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Payload size | < 400 KB (stripped) |
| Boot to shell | < 2 seconds |
| TCP throughput | > 5 Mbps (CDC-ECM bulk) |
| NAND dump time | < 60 seconds (128 MB) |
| AES GID decrypt | < 10 ms per keybag |
| Shell latency | < 5 ms (TCP), < 1 ms (UART) |
| Uptime | > 1 hour (watchdog armed) |
| Test coverage | > 80% (unit), 100% (integration) |

---

## Next Steps

1. **Today**: Complete Phase 2 (CDC-ECM + TCP stack)
2. **Week 2 end**: M2 gate (TCP shell)
3. **Week 4 end**: M3 gate (all peripherals)
4. **Week 6 end**: M4 gate (NAND + AES)
5. **Week 7 end**: M5 gate (ACE2 + SEP)
4. **Week 8 end**: M6 gate (all research)
5. **Week 10 end**: M7 gate (ship)

---

**Current Status:** Phase 1 Complete ✅ | Phase 2 In Progress 🔄

**Next Action:** Implement CDC-ECM endpoint handlers + minimal TCP stack (ARP/ICMP/TCP)
