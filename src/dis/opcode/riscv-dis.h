#ifndef RISCV_DIS_H
#define RISCV_DIS_H
#include <iosfwd>
void riscv_dump_insn(uint64_t pc, uint64_t insn, std::ostream &out, const char *indent = nullptr);
#endif
