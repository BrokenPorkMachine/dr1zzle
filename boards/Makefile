# Invoke from repository root: make -f boards/Makefile PROFILE=small
PROFILE ?= small
ifeq ($(filter $(PROFILE),small monitor),)
$(error PROFILE must be small or monitor)
endif
BUILD := build/profiles/$(PROFILE)
PROFILE_FLAGS := $(if $(filter small,$(PROFILE)),-DDRIZZLE_SMALL_PROFILE,)
PROFILE_CC ?= clang
PROFILE_LD ?= ld.lld
QEMU ?= qemu-system-aarch64
FLAGS := --target=aarch64-none-elf -march=armv8-a -mgeneral-regs-only -std=c11 -O2 -g -ffreestanding -fno-builtin -fno-stack-protector -Wall -Wextra -Werror -Iinclude -I. $(PROFILE_FLAGS)
SOURCES := arch/aarch64/start.S kernel/main.c kernel/qemu_virt.c kernel/hardware.c boards/qemu_virt.c kernel/monitor.c kernel/time.c kernel/net.c kernel/udp.c kernel/tcp.c net/wifi.c lib/console.c lib/printf.c lib/string.c lib/ctype.c lib/stdlib.c
ifeq ($(PROFILE),monitor)
SOURCES += kernel/qemu_ramfb.c kernel/display.c kernel/display_font.c kernel/display_memory.c
endif
OBJECTS := $(addprefix $(BUILD)/,$(addsuffix .o,$(basename $(SOURCES))))
.PHONY: all run test
all: $(BUILD)/monitor.elf
$(BUILD)/%.o: %.c boards/Makefile
	@mkdir -p $(dir $@)
	$(PROFILE_CC) $(FLAGS) -MMD -MP -c $< -o $@
$(BUILD)/%.o: %.S boards/Makefile
	@mkdir -p $(dir $@)
	$(PROFILE_CC) $(FLAGS) -MMD -MP -c $< -o $@
$(BUILD)/layout.ld: boards/qemu_virt.ld.S boards/qemu_budget.h
	@mkdir -p $(dir $@)
	$(PROFILE_CC) -E -P -x c $(PROFILE_FLAGS) $< -o $@
$(BUILD)/monitor.elf: $(OBJECTS) $(BUILD)/layout.ld
	$(PROFILE_LD) -T $(BUILD)/layout.ld -Map=$(BUILD)/monitor.map $(OBJECTS) -o $@
run: all
	$(QEMU) -machine virt -cpu cortex-a53 -m 128M -nographic -kernel $(BUILD)/monitor.elf
test:
	python3 tests/test_profiles.py
-include $(OBJECTS:.o=.d)
