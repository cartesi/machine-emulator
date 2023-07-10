
CFLAGS = -march=rv64i  -g0 -Wl,--gc-sections -O0 -ffreestanding -nostartfiles \
   -mcmodel=medany -static -fvisibility=hidden \
	-I$(MACHINE_EMULATOR_DEFINES_DIR)

# linker script used by the test suite Makefile to build the tested riscv target
TARGET_LINK_LD = riscv-target/cartesi/link.ld

all: $(TARGET_LINK_LD)

%.ld: %.ld.in
	$(TOOLCHAIN_PREFIX)gcc -o $@.tmp -x c $(CFLAGS) -E  $^
	grep -v '^#' $@.tmp > $@

clean:
	rm -f *.elf *.bin *.tmp *.ld
