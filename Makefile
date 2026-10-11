# A11 Research Payload - Bare Metal Build
# Target: Apple A11 (T8015) - iPhone 8/X

ARCH := aarch64
CROSS_COMPILE ?= aarch64-elf-
GNU_CC := $(shell command -v $(CROSS_COMPILE)gcc 2>/dev/null)
LLVM_OBJCOPY := $(shell command -v llvm-objcopy 2>/dev/null || test ! -x /opt/homebrew/opt/llvm/bin/llvm-objcopy || echo /opt/homebrew/opt/llvm/bin/llvm-objcopy)
HOST_CC ?= cc

ifeq ($(GNU_CC),)
CC := clang
LD := clang
TARGET_FLAGS := --target=aarch64-none-elf
OBJCOPY := $(if $(LLVM_OBJCOPY),$(LLVM_OBJCOPY),false)
OBJDUMP := objdump
NM := nm
SIZE := size
else
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)gcc
TARGET_FLAGS :=
OBJCOPY := $(CROSS_COMPILE)objcopy
OBJDUMP := $(CROSS_COMPILE)objdump
NM := $(CROSS_COMPILE)nm
SIZE := $(CROSS_COMPILE)size
endif

# Paths
SRC_DIR := src
INC_DIR := include
LINKER_DIR := linker
BUILD_DIR := build
TARGET := a11-payload
# The primary artifact is the core bootstrap; the firmware is the on-demand
# image the core (or `goat push --run`) lays down.
FW_TARGET := firmware/dr1zzle

# Source files
ASM_SRCS := $(SRC_DIR)/arch/arm64/start.S
C_SRCS := \
	$(SRC_DIR)/arch/arm64/globals.c \
	$(SRC_DIR)/arch/arm64/mmu.c \
	$(SRC_DIR)/arch/arm64/mmio.c \
	$(SRC_DIR)/arch/arm64/exception.c \
	$(SRC_DIR)/util.c \
	$(SRC_DIR)/drivers/pmgr.c \
	$(SRC_DIR)/drivers/aic.c \
	$(SRC_DIR)/drivers/nand.c \
	$(SRC_DIR)/drivers/aes.c \
	$(SRC_DIR)/drivers/aes_a9.c \
	$(SRC_DIR)/drivers/console.c \
	$(SRC_DIR)/drivers/dump.c \
	$(SRC_DIR)/drivers/uart.c \
	$(SRC_DIR)/drivers/timer.c \
	$(SRC_DIR)/drivers/gpio.c \
	$(SRC_DIR)/drivers/i2c.c \
	$(SRC_DIR)/drivers/spi.c \
	$(SRC_DIR)/drivers/watchdog.c \
	$(SRC_DIR)/drivers/usb.c \
	$(SRC_DIR)/drivers/wifi.c \
	$(SRC_DIR)/drivers/cdc_ecm.c \
	$(SRC_DIR)/drivers/usb_descriptors.c \
	$(SRC_DIR)/drivers/display_fb.c \
	$(SRC_DIR)/drivers/nand_export.c \
	$(SRC_DIR)/drivers/recfg.c \
	$(SRC_DIR)/drivers/recfg_soc.c \
	$(SRC_DIR)/drivers/sep.c \
	$(SRC_DIR)/drivers/tz.c \
	$(SRC_DIR)/ui/dashboard.c \
	$(SRC_DIR)/ui/menu.c \
	$(SRC_DIR)/drivers/display_attach.c \
	$(SRC_DIR)/drivers/font8x8.c \
	$(SRC_DIR)/fs/apfs.c \
	$(SRC_DIR)/vfs/vfs.c \
	$(SRC_DIR)/vfs/apfs_vfs.c \
	$(SRC_DIR)/stdlib.c \
	$(SRC_DIR)/core/fw_store.c \
	$(SRC_DIR)/shell/shell.c \
	$(SRC_DIR)/string.c \
	$(SRC_DIR)/research/keybag.c \
	$(SRC_DIR)/research/nand_dump.c \
	$(SRC_DIR)/research/sepos.c \
	$(SRC_DIR)/research/ace2.c \
	$(SRC_DIR)/goat/sha256.c \
	$(SRC_DIR)/goat/aes.c \
	$(SRC_DIR)/goat/asn1.c \
	$(SRC_DIR)/goat/rsa.c \
	$(SRC_DIR)/goat/util.c \
	$(SRC_DIR)/goat/goat.c \
	$(SRC_DIR)/goat/loader.c \
	$(SRC_DIR)/research_stubs.c \
	$(SRC_DIR)/net/tcp.c \
	$(SRC_DIR)/main.c

# Core bootstrap sources. This is the image actually written through the pwndfu
# command window, so it is kept to the essentials: console, timer, interrupts,
# NAND (the firmware store), USB + CDC-ECM + TCP (the goatloader), and the goat
# crypto the loader verifies a container with. Everything else -- the monitor
# shell, VFS/APFS, the dump drivers, display, wifi, i2c/spi -- lives in a
# firmware image and is brought up by that image, not here.
CORE_C_SRCS := \
	$(SRC_DIR)/arch/arm64/globals.c \
	$(SRC_DIR)/arch/arm64/mmu.c \
	$(SRC_DIR)/arch/arm64/mmio.c \
	$(SRC_DIR)/arch/arm64/exception.c \
	$(SRC_DIR)/util.c \
	$(SRC_DIR)/string.c \
	$(SRC_DIR)/drivers/pmgr.c \
	$(SRC_DIR)/drivers/aic.c \
	$(SRC_DIR)/drivers/nand.c \
	$(SRC_DIR)/drivers/console.c \
	$(SRC_DIR)/drivers/uart.c \
	$(SRC_DIR)/drivers/timer.c \
	$(SRC_DIR)/drivers/gpio.c \
	$(SRC_DIR)/drivers/i2c.c \
	$(SRC_DIR)/drivers/spi.c \
	$(SRC_DIR)/drivers/watchdog.c \
	$(SRC_DIR)/drivers/usb.c \
	$(SRC_DIR)/drivers/cdc_ecm.c \
	$(SRC_DIR)/drivers/usb_descriptors.c \
	$(SRC_DIR)/goat/sha256.c \
	$(SRC_DIR)/goat/aes.c \
	$(SRC_DIR)/goat/asn1.c \
	$(SRC_DIR)/goat/rsa.c \
	$(SRC_DIR)/goat/util.c \
	$(SRC_DIR)/goat/goat.c \
	$(SRC_DIR)/goat/loader.c \
	$(SRC_DIR)/net/tcp.c \
	$(SRC_DIR)/stdlib.c \
	$(SRC_DIR)/core/core_main.c \
	$(SRC_DIR)/core/fw_store.c

# The firmware is the old full image: every feature, linked for the SRAM tail
# and laid down on demand. It drops only the MMU translation tables -- ~590 KB
# of .bss for a translation regime this build never enables, and enough to push
# the image past the top of SRAM at its load address.
FW_C_SRCS := $(filter-out $(SRC_DIR)/arch/arm64/mmu.c,$(C_SRCS))

# Stage 1 sources (minimal bootstrap)
STAGE1_ASM_SRCS := $(SRC_DIR)/stage1/start.S
STAGE1_C_SRCS := $(SRC_DIR)/stage1/stage1.c

# Stage 2 sources (asset manager)
STAGE2_ASM_SRCS := $(SRC_DIR)/stage2/start.S
STAGE2_C_SRCS := $(SRC_DIR)/stage2/main.c

# Stage 3 sources (final payload)
STAGE3_ASM_SRCS := $(SRC_DIR)/stage3/start.S
STAGE3_C_SRCS := $(SRC_DIR)/stage3/main.c

# Object files
STAGE1_OBJS := $(STAGE1_ASM_SRCS:$(SRC_DIR)/%.S=$(BUILD_DIR)/%.o) $(STAGE1_C_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
STAGE2_OBJS := $(STAGE2_ASM_SRCS:$(SRC_DIR)/%.S=$(BUILD_DIR)/%.o) $(STAGE2_C_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
STAGE3_OBJS := $(STAGE3_ASM_SRCS:$(SRC_DIR)/%.S=$(BUILD_DIR)/%.o) $(STAGE3_C_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

OBJS := $(ASM_SRCS:$(SRC_DIR)/%.S=$(BUILD_DIR)/%.o) $(C_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

CORE_OBJS := $(ASM_SRCS:$(SRC_DIR)/%.S=$(BUILD_DIR)/%.o) $(CORE_C_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
FW_OBJS := $(ASM_SRCS:$(SRC_DIR)/%.S=$(BUILD_DIR)/%.o) $(FW_C_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Linker scripts
LDSCRIPT := $(LINKER_DIR)/a11.ld
FW_LDSCRIPT := $(LINKER_DIR)/firmware.ld
STAGE1_LDSCRIPT := $(LINKER_DIR)/stage1.ld
STAGE2_LDSCRIPT := $(LINKER_DIR)/stage2.ld
STAGE3_LDSCRIPT := $(LINKER_DIR)/stage3.ld

# SoC profile — selects which include/soc/<soc>.h is pulled in via -DSOC_<soc>.
# One binary per SoC, like the boards/ profiles. A new SoC is a new header
# under include/soc/ plus a matching #elif in include/soc.h.
SOC ?= t8015
SOC_DEFINE := -DSOC_$(SOC)

# Compiler flags
CFLAGS := -std=c11 -ffreestanding -nostdlib -nodefaultlibs
CFLAGS += -Wall -Wextra -Werror -O2 -g
CFLAGS += -march=armv8-a -mcpu=cortex-a73
CFLAGS += -I$(INC_DIR) -I$(SRC_DIR)
CFLAGS += -DARCH_AARCH64 -D__BARE_METAL__ $(SOC_DEFINE)

ASMFLAGS := -I$(INC_DIR) -I$(SRC_DIR)/arch/arm64

LDFLAGS := -nostdlib -nodefaultlibs -Wl,-T,$(LDSCRIPT) -Wl,-Map,$(BUILD_DIR)/$(TARGET).map
FW_LDFLAGS := -nostdlib -nodefaultlibs -Wl,-T,$(FW_LDSCRIPT) -Wl,-Map,$(BUILD_DIR)/$(FW_TARGET).map

# Use lld for clang bare-metal targets (avoids ld64 confusion)
ifeq ($(GNU_CC),)
LDFLAGS += -fuse-ld=lld
FW_LDFLAGS += -fuse-ld=lld
endif

SIZE_CFLAGS := $(CFLAGS) -Os

STAGE1_CFLAGS := $(SIZE_CFLAGS) -DSTAGE=1
STAGE2_CFLAGS := $(SIZE_CFLAGS) -DSTAGE=2
STAGE3_CFLAGS := $(CFLAGS) -DSTAGE=3

# Targets
.PHONY: all clean deploy debug qemu qemu-headless stage1 stage2 stage3 flash firmware

# Two artifacts: the core (default, written by `goat kload`) and the firmware
# (the full feature image, laid down by the core or `goat push --run`). They are
# separate link units that share object files, and never share a c_main: the
# core defines it in src/core/core_main.c, the firmware in src/main.c.
all: $(BUILD_DIR)/$(TARGET).bin $(BUILD_DIR)/$(FW_TARGET).bin

firmware: $(BUILD_DIR)/$(FW_TARGET).bin

$(BUILD_DIR)/$(TARGET).bin: $(BUILD_DIR)/$(TARGET).elf
	@if [ "$(OBJCOPY)" = "false" ]; then echo "error: install llvm-objcopy or GNU objcopy to create $@" >&2; exit 1; fi
	$(OBJCOPY) -O binary $< $@
	@echo "Built core $@ ($$(stat -f%z $@ 2>/dev/null || stat -c%s $@) bytes)"

$(BUILD_DIR)/$(TARGET).elf: $(CORE_OBJS) $(LDSCRIPT)
	@mkdir -p $(dir $@)
	$(LD) $(TARGET_FLAGS) $(LDFLAGS) $(CORE_OBJS) -o $@

$(BUILD_DIR)/$(FW_TARGET).bin: $(BUILD_DIR)/$(FW_TARGET).elf
	@if [ "$(OBJCOPY)" = "false" ]; then echo "error: install llvm-objcopy or GNU objcopy to create $@" >&2; exit 1; fi
	$(OBJCOPY) -O binary $< $@
	@echo "Built firmware $@ ($$(stat -f%z $@ 2>/dev/null || stat -c%s $@) bytes)"

$(BUILD_DIR)/$(FW_TARGET).elf: $(FW_OBJS) $(FW_LDSCRIPT)
	@mkdir -p $(dir $@)
	$(LD) $(TARGET_FLAGS) $(FW_LDFLAGS) $(FW_OBJS) -o $@

# The firmware record (firmware_header_t + image) is what a NAND slot holds.
# It exists so the on-NAND format is built by the same build that made the
# image; goat push remains the reliable delivery path until a flash tool has
# the page/ECC plumbing to lay the record down.
FW_RECORD := $(BUILD_DIR)/$(FW_TARGET).fw

firmware-record: $(FW_RECORD)

$(FW_RECORD): $(BUILD_DIR)/$(FW_TARGET).bin $(BUILD_DIR)/$(FW_TARGET).elf scripts/mkfirmware.py
	@mkdir -p $(dir $@)
	python3 scripts/mkfirmware.py $(BUILD_DIR)/$(FW_TARGET).bin \
		--elf $(BUILD_DIR)/$(FW_TARGET).elf \
		--load-base 0x180100000 \
		--name dr1zzle \
		--out $@

# Stage 1 needs: minimal uart, timer, nand, mmio, string, util (stage1 versions)
STAGE1_DEPS_OBJS := \
	$(BUILD_DIR)/stage1/uart_stage1.o \
	$(BUILD_DIR)/stage1/timer_stage1.o \
	$(BUILD_DIR)/stage1/nand_stage1.o \
	$(BUILD_DIR)/stage1/string_stage1.o \
	$(BUILD_DIR)/stage1/util_stage1.o \
	$(BUILD_DIR)/drivers/mmio.o

# Stage 1: Minimal bootstrap (32 KB)
stage1: $(BUILD_DIR)/stage1.bin

$(BUILD_DIR)/stage1.elf: $(STAGE1_OBJS) $(STAGE1_DEPS_OBJS) $(STAGE1_LDSCRIPT)
	@mkdir -p $(dir $@)
	$(LD) $(TARGET_FLAGS) -nostdlib -nodefaultlibs -Wl,-T,$(STAGE1_LDSCRIPT) -Wl,-Map,$(BUILD_DIR)/stage1.map $(STAGE1_OBJS) $(STAGE1_DEPS_OBJS) -o $@

$(BUILD_DIR)/stage1.bin: $(BUILD_DIR)/stage1.elf
	@if [ "$(OBJCOPY)" = "false" ]; then echo "error: install llvm-objcopy" >&2; exit 1; fi
	$(OBJCOPY) -O binary $< $@
	@echo "Built Stage 1: $$(stat -f%z $@ 2>/dev/null || stat -c%s $@) bytes"

# Stage 2: Asset manager (128 KB)
stage2: $(BUILD_DIR)/stage2.bin

$(BUILD_DIR)/stage2.elf: $(STAGE2_OBJS) $(STAGE2_LDSCRIPT)
	@mkdir -p $(dir $@)
	$(LD) $(TARGET_FLAGS) -nostdlib -nodefaultlibs -Wl,-T,$(STAGE2_LDSCRIPT) -Wl,-Map,$(BUILD_DIR)/stage2.map $(STAGE2_OBJS) -o $@

$(BUILD_DIR)/stage2.bin: $(BUILD_DIR)/stage2.elf
	@if [ "$(OBJCOPY)" = "false" ]; then echo "error: install llvm-objcopy" >&2; exit 1; fi
	$(OBJCOPY) -O binary $< $@
	@echo "Built Stage 2: $$(stat -f%z $@ 2>/dev/null || stat -c%s $@) bytes"

# Stage 3: Final payload (unbounded)
stage3: $(BUILD_DIR)/stage3.elf

$(BUILD_DIR)/stage3.elf: $(STAGE3_OBJS) $(STAGE3_LDSCRIPT)
	@mkdir -p $(dir $@)
	$(LD) $(TARGET_FLAGS) -nostdlib -nodefaultlibs -Wl,-T,$(STAGE3_LDSCRIPT) -Wl,-Map,$(BUILD_DIR)/stage3.map $(STAGE3_OBJS) -o $@

# Build flash image
flash: $(BUILD_DIR)/flash.bin

$(BUILD_DIR)/flash.bin: $(BUILD_DIR)/stage1.bin $(BUILD_DIR)/stage2.bin $(BUILD_DIR)/stage3.elf
	python3 scripts/build_flash.py --stage1 $(BUILD_DIR)/stage1.bin --stage2 $(BUILD_DIR)/stage2.bin --stage3 $(BUILD_DIR)/stage3.elf --output $(BUILD_DIR)/flash.bin

# Generic object rules. More specific pattern rules elsewhere (goat/, shell/,
# drivers/usb.o, the stage trees) win because make prefers the shortest stem.
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.S
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(ASMFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(CFLAGS) -c $< -o $@

# src/goat/ is the size-budgeted tree: see SIZE_CFLAGS above.
$(BUILD_DIR)/goat/%.o: $(SRC_DIR)/goat/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(SIZE_CFLAGS) -c $< -o $@

# Size-optimized files to keep flat image under 0x18001C000
$(BUILD_DIR)/shell/shell.o: $(SRC_DIR)/shell/shell.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(SIZE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/drivers/usb.o: $(SRC_DIR)/drivers/usb.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(SIZE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/drivers/mmio.o: $(SRC_DIR)/drivers/mmio.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/drivers/wifi.o: $(SRC_DIR)/drivers/wifi.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(SIZE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/drivers/cdc_ecm.o: $(SRC_DIR)/drivers/cdc_ecm.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(SIZE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/drivers/display_fb.o: $(SRC_DIR)/drivers/display_fb.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(SIZE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/net/tcp.o: $(SRC_DIR)/net/tcp.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(SIZE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/arch/arm64/exception.o: $(SRC_DIR)/arch/arm64/exception.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(SIZE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/ui/dashboard.o: $(SRC_DIR)/ui/dashboard.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(SIZE_CFLAGS) -c $< -o $@

# Stage-specific compilation rules
$(BUILD_DIR)/stage1/%.o: $(SRC_DIR)/stage1/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(STAGE1_CFLAGS) -c $< -o $@

$(BUILD_DIR)/stage1/%.o: $(SRC_DIR)/stage1/%.S
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(ASMFLAGS) -x assembler-with-cpp -c $< -o $@

$(BUILD_DIR)/stage2/%.o: $(SRC_DIR)/stage2/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(STAGE2_CFLAGS) -c $< -o $@

# Explicit rule for Stage 2 start.S
$(BUILD_DIR)/stage2/start.o: $(SRC_DIR)/stage2/start.S
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(ASMFLAGS) -x assembler-with-cpp -c $< -o $@

$(BUILD_DIR)/stage3/%.o: $(SRC_DIR)/stage3/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(STAGE3_CFLAGS) -c $< -o $@

$(BUILD_DIR)/stage3/%.o: $(SRC_DIR)/stage3/%.S
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(ASMFLAGS) -x assembler-with-cpp -c $< -o $@



clean:
	rm -rf $(BUILD_DIR)

deploy: $(BUILD_DIR)/$(TARGET).elf
	./goat/goat kload $(BUILD_DIR)/$(TARGET).elf

# Stage the full firmware build over USB and enter it (requires a sealing key).
#    make deploy-firmware KEY_HEX=<hex> CERT=<goat-key.json>
deploy-firmware: $(BUILD_DIR)/$(FW_TARGET).bin
	./goat/goat seal $(BUILD_DIR)/$(FW_TARGET).bin \
		--cert $(if $(CERT),$(CERT),goat-key.json) \
		--key-hex $(KEY_HEX) \
		--load-base 0x180100000 \
		--entry-off 0x1000 \
		--out $(BUILD_DIR)/$(FW_TARGET).g1
	./goat/goat push $(BUILD_DIR)/$(FW_TARGET).g1 --key-hex $(KEY_HEX) --run

debug: $(BUILD_DIR)/$(TARGET).elf
	$(OBJDUMP) -d $< > $(BUILD_DIR)/$(TARGET).asm
	$(NM) -n $< > $(BUILD_DIR)/$(TARGET).sym

qemu:
	scripts/run-qemu.sh --display

qemu-headless:
	scripts/run-qemu.sh --headless

size: $(BUILD_DIR)/$(TARGET).elf
	$(SIZE) $<

.PHONY: all clean deploy debug size qemu qemu-headless stage1 stage2 stage3 flash

# Portable, budget-enforced QEMU hardware profiles (separate from A11 payload).
PROFILE ?= small
.PHONY: profiles profiles-test profiles-qemu host-test phase4-test goat-test loader-test sep-test soc-test rpwn-test menu-test
profiles:
	$(MAKE) -f boards/Makefile PROFILE=$(PROFILE)
profiles-test:
	$(MAKE) -f boards/Makefile test
profiles-qemu:
	$(MAKE) -f boards/Makefile PROFILE=$(PROFILE) run

# Complete host-side check. PROFILE_LD may be overridden when the local
# LLVM/LLD installation needs an explicit matching linker wrapper.
host-test:
	@if [ -n "$(PROFILE_LD)" ]; then \
		PROFILE_LD="$(PROFILE_LD)" python3 -m unittest discover -s tests -p 'test_*.py'; \
	else \
		python3 -m unittest discover -s tests -p 'test_*.py'; \
	fi

phase4-test:
	python3 tests/test_phase4.py

goat-test:
	cargo test --locked --manifest-path goat-rust/Cargo.toml

loader-test:
	cargo test --locked --manifest-path goat-rust/Cargo.toml

# The SEP work: the mailbox protocol against pongoOS and captured traces, and
# the shell-wrapper layer that owns the static driver instance.
sep-test:
	python3 tests/test_sep.py
	python3 tests/test_sepos_wrappers.py

# The SoC registry is checked against the vendored checkm8 sources and, when
# present, the local usbliter8 reference. No device is involved.
soc-test:
	python3 tests/test_socs.py

# RPWN is the Rust-native DFU driver; keep its byte-level suite in the host checks.
rpwn-test:
	cargo test --locked --manifest-path rpwn/rust/Cargo.toml

# Host test for the on-screen menu: panel/pane layout and bounded scrolling.
menu-test:
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -O1 -g -I$(INC_DIR) -I$(SRC_DIR) \
		tests/menu_host_test.c $(SRC_DIR)/ui/menu.c $(SRC_DIR)/drivers/font8x8.c \
		-o $(BUILD_DIR)/menu_host_test
	$(BUILD_DIR)/menu_host_test
