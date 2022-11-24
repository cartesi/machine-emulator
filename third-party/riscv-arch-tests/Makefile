MACHINE_EMULATOR_DEFINES_DIR ?= $(abspath ../../lib/machine-emulator-defines)
EMULATOR_ROM ?= $(abspath ../../../rom.bin)

RISCV_ARCH_TEST_PROJ = riscv-arch-test
RISCV_ARCHTEST_BASE_URL = https://github.com/riscv-non-isa/$(RISCV_ARCH_TEST_PROJ)/archive
RISCV_ARCHTEST_RELEASE = 2.7.3
RISCV_ARCHTEST_URL = $(RISCV_ARCHTEST_BASE_URL)/$(RISCV_ARCHTEST_RELEASE).tar.gz
SRCDIR = $(abspath src)
DEPDIR = third-party
RISCV_ARCH_TEST = $(DEPDIR)/$(RISCV_ARCH_TEST_PROJ)-$(RISCV_ARCHTEST_RELEASE)
TEST_BOOTSTRAP = $(abspath src/bootstrap.bin)
RUN_ARCH_TEST = $(abspath src/run-rv64i-arch-test.lua)

# Arguments required by the riscv arch test suite
XLEN = 64
RISCV_TARGET = cartesi
RISCV_ISA = rv64i
TARGETDIR = $(abspath src/riscv-target)
RISCV_DEVICE = I
RUN_RISCV_ARCH_TESTS = \
	make -C $(RISCV_ARCH_TEST) \
		XLEN=$(XLEN) \
		RISCV_TARGET=$(RISCV_TARGET) \
		RISCV_ISA=$(RISCV_ISA) \
		TARGETDIR=$(TARGETDIR) \
		RISCV_DEVICE=$(RISCV_DEVICE) \
		TEST_BOOTSTRAP=$(TEST_BOOTSTRAP) \
		EMULATOR_ROM=$(EMULATOR_ROM) \
		RUN_ARCH_TEST=$(RUN_ARCH_TEST) \
		MACHINE_EMULATOR_DEFINES_DIR=$(MACHINE_EMULATOR_DEFINES_DIR)

all: rv64i-arch-tests

rv64i-arch-tests:  $(RISCV_ARCH_TEST) $(SRCDIR)
	$(RUN_RISCV_ARCH_TESTS)

$(RISCV_ARCH_TEST): $(DEPDIR)
	wget  -qO-  $(RISCV_ARCHTEST_URL) | tar -xz -C $(DEPDIR)

$(DEPDIR):
	mkdir -p $@

$(SRCDIR):
	make -C $@ MACHINE_EMULATOR_DEFINES_DIR=$(MACHINE_EMULATOR_DEFINES_DIR) \

clean:
	make -C $(SRCDIR) clean
	if [ -d $(RISCV_ARCH_TEST) ]; then $(RUN_RISCV_ARCH_TESTS) clean; fi
  
depclean: clean
	rm -rf $(RISCV_ARCH_TEST)
  
.PHONY: all rv64i-arch-tests $(SRCDIR) clean depclean

