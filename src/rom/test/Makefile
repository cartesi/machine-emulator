BASE=/opt/riscv
COMPILER_PATH=$(BASE)/toolchain/linux/rv64ima-lp64/bin
CC=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-gcc
CXX=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-g++
OBJCOPY=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-objcopy
OBJDUMP=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-objdump
OBJSTRIP=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-strip
CFLAGS=-static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles -I$(BASE)/emulator

BUILD_DIR ?= ./build

SRCS  := $(wildcard *.S)
TMPS  := $(SRCS:.S=.out)
BINS  := $(TMPS:%.out=$(BUILD_DIR)/%.bin)
DUMPS := $(TMPS:%.out=$(BUILD_DIR)/%.dump)

.DEFAULT_GOAL := all

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.out
	$(OBJCOPY) -S -O binary $< $@

$(BUILD_DIR)/%.dump: $(BUILD_DIR)/%.out
	$(OBJDUMP) -d $< > $@

$(BUILD_DIR):
	$(MKDIR_P) $(BUILD_DIR)

# assembly
$(BUILD_DIR)/%.out: %.S $(BUILD_DIR)
	$(CC) $(CFLAGS) $(patsubst %.ld,-T%.ld,$(wildcard $(patsubst %.S,%.ld,$<))) -o $@ $<

.PHONY: all clean copy
all: $(BINS) $(DUMPS)

clean:
	@$(RM) -r $(BUILD_DIR)

# Should be run inside docker container
copy: all
	cp $(BUILD_DIR)/*.bin $(BUILD_DIR)/*.dump ../emulator/tests/

MKDIR_P ?= mkdir -p
