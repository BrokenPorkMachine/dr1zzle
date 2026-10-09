# A11 Research Payload - Bare Metal Build
# Target: Apple A11 (T8015) - iPhone 8/X

ARCH := aarch64
CROSS_COMPILE ?= aarch64-none-elf-
GNU_CC := $(shell command -v $(CROSS_COMPILE)gcc 2>/dev/null)
LLVM_OBJCOPY := $(shell command -v llvm-objcopy 2>/dev/null || test ! -x /opt/homebrew/opt/llvm/bin/llvm-objcopy || echo /opt/homebrew/opt/llvm/bin/llvm-objcopy)

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

# Source files. Keep this explicit: src/research contains standalone hardware
# experiments that are not part of the payload build.
ASM_SRCS := $(SRC_DIR)/arch/arm64/start.S
C_SRCS := \
	$(SRC_DIR)/arch/arm64/mmu.c \
	$(SRC_DIR)/arch/arm64/exception.c \
	$(SRC_DIR)/util.c \
	$(SRC_DIR)/drivers/uart.c \
	$(SRC_DIR)/drivers/timer.c \
	$(SRC_DIR)/drivers/usb.c \
	$(SRC_DIR)/drivers/usb_descriptors.c \
	$(SRC_DIR)/shell/shell.c \
	$(SRC_DIR)/string.c \
	$(SRC_DIR)/research_stubs.c \
	$(SRC_DIR)/net/tcp.c \
	$(SRC_DIR)/main.c
OBJS := $(ASM_SRCS:$(SRC_DIR)/%.S=$(BUILD_DIR)/%.o) $(C_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Linker script
LDSCRIPT := $(LINKER_DIR)/a11.ld

# Compiler flags
CFLAGS := -std=c11 -ffreestanding -nostdlib -nodefaultlibs
CFLAGS += -Wall -Wextra -Werror -O2 -g
CFLAGS += -march=armv8-a -mcpu=cortex-a73
CFLAGS += -I$(INC_DIR) -I$(SRC_DIR)
CFLAGS += -DARCH_AARCH64 -D__BARE_METAL__

ASMFLAGS := -I$(INC_DIR) -I$(SRC_DIR)/arch/arm64

LDFLAGS := -nostdlib -nodefaultlibs -Wl,-T,$(LDSCRIPT) -Wl,-Map,$(BUILD_DIR)/$(TARGET).map

# Targets
.PHONY: all clean deploy debug qemu qemu-headless

all: $(BUILD_DIR)/$(TARGET).bin

$(BUILD_DIR)/$(TARGET).bin: $(BUILD_DIR)/$(TARGET).elf
	@if [ "$(OBJCOPY)" = "false" ]; then echo "error: install llvm-objcopy or GNU objcopy to create $@" >&2; exit 1; fi
	$(OBJCOPY) -O binary $< $@
	@echo "Built $@ ($$(stat -f%z $@ 2>/dev/null || stat -c%s $@) bytes)"

$(BUILD_DIR)/$(TARGET).elf: $(OBJS) $(LDSCRIPT)
	@mkdir -p $(dir $@)
	$(LD) $(TARGET_FLAGS) $(LDFLAGS) $(OBJS) -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.S
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(ASMFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

deploy: $(BUILD_DIR)/$(TARGET).bin
	ipwndfu -p
	ipwndfu -l $(BUILD_DIR)/$(TARGET).bin

debug: $(BUILD_DIR)/$(TARGET).elf
	$(OBJDUMP) -d $< > $(BUILD_DIR)/$(TARGET).asm
	$(NM) -n $< > $(BUILD_DIR)/$(TARGET).sym

qemu: $(BUILD_DIR)/$(TARGET).elf
	scripts/run-qemu.sh --display --no-build

qemu-headless: $(BUILD_DIR)/$(TARGET).elf
	scripts/run-qemu.sh --headless --no-build

size: $(BUILD_DIR)/$(TARGET).elf
	$(SIZE) $<

.PHONY: all clean deploy debug size qemu qemu-headless
