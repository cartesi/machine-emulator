#ifndef MACHINE_CONFIG_H
#define MACHINE_CONFIG_H

#include <cstdint>
#include <string>
#include <vector>
#include <boost/container/static_vector.hpp>

namespace cartesi {

struct processor_config final {
    processor_config():
        x{},
        pc{0},
        mvendorid{0},
        marchid{0},
        mimpid{0},
        mcycle{0},
        minstret{0},
        mstatus{0},
        mtvec{0},
        mscratch{0},
        mepc{0},
        mcause{0},
        mtval{0},
        misa{0},
        mie{0},
        mip{0},
        medeleg{0},
        mideleg{0},
        mcounteren{0},
        stvec{0},
        sscratch{0},
        sepc{0},
        scause{0},
        stval{0},
        satp{0},
        scounteren{0},
        ilrsc{0},
        iflags{0},
        backing{} {
        ;
    }
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
    ram_config(): length{0}, backing{} { ; }
    uint64_t length;
    std::string backing;
};

struct rom_config final {
    rom_config(): bootargs{}, backing{} { ; }
    std::string bootargs;
    std::string backing;
};

struct flash_config final {
    flash_config(): start{0}, length{0}, shared{false}, label{}, backing{} { ; }
    uint64_t start;
    uint64_t length;
    bool shared;
    std::string label;
    std::string backing;
};

struct clint_config final {
    clint_config(): mtimecmp{0}, backing{} { ; }
    uint64_t mtimecmp;
    std::string backing;
};

struct htif_config final {
    htif_config(): fromhost{0}, tohost{0}, backing{} { ; }
    uint64_t fromhost;
    uint64_t tohost;
    std::string backing;
};

#define FLASH_MAX 8

struct machine_config final {
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
