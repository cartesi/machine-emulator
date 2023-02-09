TOOLCHAIN_IMAGE ?= cartesi/toolchain:0.11.0
TOOLCHAIN_PREFIX ?= riscv64-cartesi-linux-gnu-

MACHINE_EMULATOR_DEFINES_DIR ?= $(abspath ../../lib/machine-emulator-defines)
CONTAINER_MACHINE_EMULATOR_DEFINES_DIR := /machine-emulator-defines

RUN_TOOLCHAIN=docker run --rm  \
	-e USER=$$(id -u -n) \
	-e GROUP=$$(id -g -n) \
	-e UID=$$(id -u) \
	-e GID=$$(id -g) \
	-v `pwd`:/src  \
	-v $(MACHINE_EMULATOR_DEFINES_DIR):$(CONTAINER_MACHINE_EMULATOR_DEFINES_DIR) \
	-w /src \
	-t ${TOOLCHAIN_IMAGE} 

CFLAGS = -march=rv64i  -g0 -Wl,--gc-sections -O0 -ffreestanding -nostartfiles \
   -mcmodel=medany -static -fvisibility=hidden \
	-I$(CONTAINER_MACHINE_EMULATOR_DEFINES_DIR)

# linker script used by the test suite Makefile to build the tested riscv target
TARGET_LINK_LD = riscv-target/cartesi/link.ld

all: $(TARGET_LINK_LD)

%.ld: %.ld.in
	$(RUN_TOOLCHAIN) $(TOOLCHAIN_PREFIX)gcc -o $@.tmp -x c $(CFLAGS) -E  $^
	grep -v '^#' $@.tmp > $@

clean:
	rm -f *.elf *.bin *.tmp *.ld
