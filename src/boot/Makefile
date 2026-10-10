# dr1zzle boot Makefile

BOOT_SRCS := \
	src/boot/patches.S \
	src/boot/stage3.c \
	src/boot/clearhook.S

BOOT_OBJS := $(BOOT_SRCS:src/boot/%.S=build/boot/%.o) $(BOOT_SRCS:src/boot/%.c=build/boot/%.o)

BOOT_CFLAGS := -std=c11 -ffreestanding -nostdlib -nodefaultlibs -Wall -Wextra -Werror -O2 -g -march=armv8-a -mcpu=cortex-a73 -Iinclude -Isrc -Iinclude/boot
BOOT_ASMFLAGS := -Iinclude -Isrc

# Include in main build
SRC_DIR := src
INC_DIR := include
LINKER_DIR := linker
BUILD_DIR := build
TARGET := a11-payload

ASM_SRCS += $(BOOT_SRCS:src/boot/%.S=src/boot/%.S)
C_SRCS += $(BOOT_SRCS:src/boot/%.c=src/boot/%.c)
OBJS += $(BOOT_OBJS)

$(BUILD_DIR)/boot/%.o: src/boot/%.S
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(BOOT_ASMFLAGS) $(BOOT_CFLAGS) -c $< -o $@

$(BUILD_DIR)/boot/%.o: src/boot/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TARGET_FLAGS) $(BOOT_CFLAGS) -c $< -o $@