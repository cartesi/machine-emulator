MACHINE_EMULATOR_DEFINES_DIR ?= $(abspath ../../src)
RISCV_ARCH_TEST_PROJ = riscv-arch-test
RISCV_ARCHTEST_BASE_URL = https://github.com/riscv-non-isa/$(RISCV_ARCH_TEST_PROJ)/archive
RISCV_ARCHTEST_RELEASE = 2.7.4
RISCV_ARCHTEST_URL = $(RISCV_ARCHTEST_BASE_URL)/$(RISCV_ARCHTEST_RELEASE).tar.gz
SRCDIR = $(abspath src)
DEPDIR = third-party
RISCV_ARCH_TEST = $(DEPDIR)/$(RISCV_ARCH_TEST_PROJ)-$(RISCV_ARCHTEST_RELEASE)
LUA ?= lua5.4
RUN_ARCH_TEST = $(LUA) $(abspath src/run-rv64i-arch-test.lua)
TOOLCHAIN_PREFIX ?= riscv64-cartesi-linux-gnu-

# Arguments required by the riscv arch test suite
XLEN = 64
RISCV_TARGET = cartesi
RISCV_ISA = rv64i
TARGETDIR = $(abspath src/riscv-target)
RISCV_DEVICE = I
JOBS=-j1

export MACHINE_EMULATOR_DEFINES_DIR
export TOOLCHAIN_PREFIX
export RISCV_ARCH_TEST
export RUN_ARCH_TEST

export XLEN
export RISCV_TARGET
export RISCV_ISA
export TARGETDIR
export RISCV_DEVICE
export JOBS

DOWNLOADDIR := $(DEPDIR)/downloads
RISCV_ARCHT_TEST_SOURCE := $(DOWNLOADDIR)/$(RISCV_ARCHTEST_RELEASE).tar.gz
SHASUMFILES := $(RISCV_ARCHT_TEST_SOURCE)

all: rv64i-arch-tests

rv64i-arch-tests: $(RISCV_ARCH_TEST) $(SRCDIR)
	$(MAKE) -C $(RISCV_ARCH_TEST) build

run: $(RISCV_ARCH_TEST) $(SRCDIR)
	$(MAKE) -C $(RISCV_ARCH_TEST) verify

$(RISCV_ARCH_TEST): $(RISCV_ARCHT_TEST_SOURCE)
	tar -xzf $(RISCV_ARCHT_TEST_SOURCE) -C /tmp/ --no-same-owner
	mv /tmp/$(RISCV_ARCH_TEST_PROJ)-$(RISCV_ARCHTEST_RELEASE) $(RISCV_ARCH_TEST)

$(SHASUMFILES):
	@mkdir -p $(DOWNLOADDIR)
	@wget -nc -P $(DOWNLOADDIR) $(RISCV_ARCHTEST_URL)
	@$(MAKE) checksum

downloads: $(SHASUMFILES)

$(DEPDIR):
	mkdir -p $@

$(SRCDIR):
	$(MAKE)	-C $@

clean:
	$(MAKE) -C $(SRCDIR) clean
	if [ -d $(RISCV_ARCH_TEST) ]; then $(MAKE) -C $(RISCV_ARCH_TEST) clean; fi

depclean:
	rm -rf $(DEPDIR)
	$(MAKE) clean

shasumfile: $(SHASUMFILES)
	shasum -a 256 $^ > $@

checksum: $(SHASUMFILES)
	@shasum -ca 256 shasumfile

.PHONY: all rv64i-arch-tests $(SRCDIR) clean depclean
