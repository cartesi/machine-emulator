#ifndef EMULATOR_CONFIG_H
#define EMULATOR_CONFIG_H

#include <cstdint>
#include <string>
#include <vector>

struct processor_config {
    uint64_t x[32];
    uint64_t pc;
    uint64_t mvendorid;
    uint64_t marchid;
    uint64_t mimpid;
    uint64_t mcycle;
    uint64_t minstret;
    uint64_t mstatus;
    uint64_t mtvec;
    uint64_t mscratch;
    uint64_t mepc;
    uint64_t mcause;
    uint64_t mtval;
    uint64_t misa;
    uint64_t mie;
    uint64_t mip;
    uint64_t medeleg;
    uint64_t mideleg;
    uint64_t mcounteren;
    uint64_t stvec;
    uint64_t sscratch;
    uint64_t sepc;
    uint64_t scause;
    uint64_t stval;
    uint64_t satp;
    uint64_t scounteren;
    uint64_t ilrsc;
    uint64_t iflags;
    std::string backing;
};

struct ram_config {
    uint64_t length;
    std::string backing;
};

struct rom_config {
    std::string bootargs;
    std::string backing;
};

struct flash_config {
    uint64_t start;
    uint64_t length;
    bool shared;
    std::string label;
    std::string backing;
};

struct clint_config {
    uint64_t mtimecmp;
    std::string backing;
};

struct htif_config {
    uint64_t fromhost;
    uint64_t tohost;
    std::string backing;
};

struct emulator_config {
    processor_config processor;
    ram_config ram;
    rom_config rom;
    std::vector<flash_config> flash;
    clint_config clint;
    htif_config htif;
    bool interactive;
};

#endif
