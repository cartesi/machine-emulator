#include <iostream>
#include <cstdio>

#include "opcode/riscv-dis.h"

int main(void) {
    uint64_t pc, insn;
    while (scanf("%lx: %lx", &pc, &insn) == 2) {
        riscv_dump_insn(pc, insn, std::cerr);
        std::cerr << '\n';
    }
    return 0;
}
