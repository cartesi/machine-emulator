#ifndef MACHINE_CONFIG_H
#define MACHINE_CONFIG_H

#include <cstdint>
#include <string>
#include <boost/container/static_vector.hpp>

namespace cartesi {

struct processor_config final {
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

struct ram_config final {
    uint64_t length;
    std::string backing;
};

struct rom_config final {
    std::string bootargs;
    std::string backing;
};

struct flash_config final {
    uint64_t start;
    uint64_t length;
    bool shared;
    std::string label;
    std::string backing;
};

struct clint_config final {
    uint64_t mtimecmp;
    std::string backing;
};

struct htif_config final {
    uint64_t fromhost;
    uint64_t tohost;
    std::string backing;
};

#define FLASH_MAX 8

struct machine_config final {
    /// \brief Default constructor
    /// \details Fills out machine with important non-default values to
    /// several processor registers, and default (zero/empty/false)
    //value
    machine_config();
    processor_config processor;
    ram_config ram;
    rom_config rom;
    boost::container::static_vector<flash_config, FLASH_MAX> flash;
    clint_config clint;
    htif_config htif;
    bool interactive;
};

} // namespace cartesi

#endif
