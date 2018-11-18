ELF=/opt/riscv/toolchain/elf/rv64ima-lp64/bin/
ELFCC=$(ELF)/riscv64-unknown-elf-gcc
ELFOBJCOPY=$(ELF)/riscv64-unknown-elf-objcopy
ELFOBJDUMP=$(ELF)/riscv64-unknown-elf-objdump
ELFCFLAGS=-static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles

rom.bin: rom
	$(ELFOBJCOPY) -S -O binary rom rom.bin
	$(ELFOBJDUMP) -d rom > rom.dump

rom: rom.S ROM.ld
	$(ELFCC) $(ELFCFLAGS) -TROM.ld -o rom rom.S
