BASE=/opt/riscv
COMPILER_PATH=$(BASE)/toolchain/linux/rv64ima-lp64/bin
CC=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-gcc
CXX=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-g++
AS=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-as
OBJCOPY=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-objcopy
OBJDUMP=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-objdump
OBJSTRIP=$(COMPILER_PATH)/riscv64-unknown-linux-gnu-strip
CFLAGS=-static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles -I$(BASE)/emulator -I$(BASE)/dtc/libfdt
CXXFLAGS=-static -fno-exceptions -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles -I$(BASE)/emulator -I$(BASE)/dtc/libfdt

TARGET_EXEC ?= rom
FINAL_EXEC ?= $(TARGET_EXEC).bin

BUILD_DIR ?= ./build
SRC_DIRS ?= .

SRCS := $(shell find $(SRC_DIRS) -name  "*.cpp" -or -name "*.c" -or -name "*.S")
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

LIBFDT := /opt/riscv/dtc/libfdt/libfdt.a

LDIN := rom.in.ld
LDOUT := $(BUILD_DIR)/rom.ld

INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CPPFLAGS ?= $(INC_FLAGS) -MMD -MP
LDFLAGS ?= -T$(LDOUT)

$(BUILD_DIR)/$(FINAL_EXEC): $(BUILD_DIR)/$(TARGET_EXEC)
	$(OBJDUMP) -d $(BUILD_DIR)/$(TARGET_EXEC) > $(BUILD_DIR)/$(TARGET_EXEC).dump
	$(OBJCOPY) -S -O binary $(BUILD_DIR)/$(TARGET_EXEC) $(BUILD_DIR)/$(FINAL_EXEC)

$(LDOUT): $(LDIN)
	$(CC) -E -x c $(CFLAGS) $(LDIN) | grep -v '^#' >> $(LDOUT)

$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS) $(LDOUT)
	$(CC) $(OBJS) -o $@ $(LIBFDT) $(CFLAGS) $(LDFLAGS)

# assembly
$(BUILD_DIR)/%.S.o: %.S
	$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# c source
$(BUILD_DIR)/%.c.o: %.c
	$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# c++ source
$(BUILD_DIR)/%.cpp.o: %.cpp
	$(MKDIR_P) $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@


.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

-include $(DEPS)

MKDIR_P ?= mkdir -p
