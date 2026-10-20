KP_DIR ?= ../KernelPatch
CC ?= aarch64-linux-gnu-gcc
OBJCOPY ?= aarch64-linux-gnu-objcopy
CFLAGS = -O2 -Wall -Wextra -std=gnu11 -fno-PIC -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables -mgeneral-regs-only -ffixed-x18 -mno-outline-atomics -fno-builtin
INCLUDES = -I$(KP_DIR)/kernel -I$(KP_DIR)/kernel/include -I$(KP_DIR)/kernel/patch/include -I$(KP_DIR)/kernel/linux/include -I$(KP_DIR)/kernel/linux/security/selinux/include -I$(KP_DIR)/kernel/linux/arch/arm64/include
all: k40_selinux_avd_audit.kpm
k40_selinux_avd_audit.kpm: k40_selinux_avd_audit.o
	$(CC) -r -nostdlib -Wl,--no-eh-frame-hdr -o $@ $^
	$(OBJCOPY) --remove-section=.eh_frame --remove-section=.rela.eh_frame $@
k40_selinux_avd_audit.o: k40_selinux_avd_audit.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<
clean:
	rm -f *.o *.kpm
.PHONY: all clean
