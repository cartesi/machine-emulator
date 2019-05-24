BASE=/opt/riscv
COMPILER_PATH=$(BASE)/toolchain/linux/rv64ima-lp64/bin
CC=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-gcc
CXX=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-g++
OBJCOPY=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-objcopy
OBJDUMP=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-objdump
OBJSTRIP=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-strip
CFLAGS=-static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles -I$(BASE)/emulator

bootstrap.bin: bootstrap
	$(OBJCOPY) -S -O binary bootstrap bootstrap.bin
	$(OBJDUMP) -d bootstrap > bootstrap.dump

bootstrap: bootstrap.S bootstrap.ld
	$(CC) $(CFLAGS) -Tbootstrap.ld -o bootstrap bootstrap.S

.PHONY: clean

clean:
	$(RM) -rf bootstrap bootstrap.bin bootstrap.dump
