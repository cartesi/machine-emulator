/* RISC-V disassembler
   Copyright (C) 2011-2022 Free Software Foundation, Inc.

   Contributed by Andrew Waterman (andrew@sifive.com).
   Based on MIPS target.

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

#include "../elf/riscv.h"
#include "../opcode/riscv.h"

#include <cctype>
#include <cstdint>
#include <iostream>
#include <iomanip>

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

static const char *const *riscv_gpr_names = riscv_gpr_names_abi;
static const char *const *riscv_fpr_names = riscv_fpr_names_abi;

/* Print one argument from an array.  */

static void arg_print(unsigned long val, const char *const *array, size_t size, std::ostream &out) {
    const char *s = val >= size || array[val] == NULL ? "unknown" : array[val];
    out << s;
}

/* Print insn arguments for 32/64-bit code.  */

static void riscv_dump_insn_args(const char *oparg, uint64_t pc, uint64_t l, std::ostream &out) {
    int rs1 = (l >> OP_SH_RS1) & OP_MASK_RS1;
    int rd = (l >> OP_SH_RD) & OP_MASK_RD;
    const char *opargStart;

    if (*oparg != '\0')
        out << "\t";

    for (; *oparg != '\0'; oparg++) {
        opargStart = oparg;
        switch (*oparg) {
            case 'C': /* RVC */
                switch (*++oparg) {
                    case 's': /* RS1 x8-x15.  */
                    case 'w': /* RS1 x8-x15.  */
                        out << riscv_gpr_names[EXTRACT_OPERAND(CRS1S, l) + 8];
                        break;
                    case 't': /* RS2 x8-x15.  */
                    case 'x': /* RS2 x8-x15.  */
                        out << riscv_gpr_names[EXTRACT_OPERAND(CRS2S, l) + 8];
                        break;
                    case 'U': /* RS1, constrained to equal RD.  */
                        out << riscv_gpr_names[rd];
                        break;
                    case 'c': /* RS1, constrained to equal sp.  */
                        out << riscv_gpr_names[X_SP];
                        break;
                    case 'V': /* RS2 */
                        out << riscv_gpr_names[EXTRACT_OPERAND(CRS2, l)];
                        break;
                    case 'o':
                    case 'j':
                        out << (int) EXTRACT_CITYPE_IMM(l);
                        break;
                    case 'k':
                        out << (int) EXTRACT_CLTYPE_LW_IMM(l);
                        break;
                    case 'l':
                        out << (int) EXTRACT_CLTYPE_LD_IMM(l);
                        break;
                    case 'm':
                        out << (int) EXTRACT_CITYPE_LWSP_IMM(l);
                        break;
                    case 'n':
                        out << (int) EXTRACT_CITYPE_LDSP_IMM(l);
                        break;
                    case 'K':
                        out << (int) EXTRACT_CIWTYPE_ADDI4SPN_IMM(l);
                        break;
                    case 'L':
                        out << (int) EXTRACT_CITYPE_ADDI16SP_IMM(l);
                        break;
                    case 'M':
                        out << (int) EXTRACT_CSSTYPE_SWSP_IMM(l);
                        break;
                    case 'N':
                        out << (int) EXTRACT_CSSTYPE_SDSP_IMM(l);
                        break;
                    case 'p':
                        out << "0x" << std::hex << (int) (EXTRACT_CBTYPE_IMM(l) + pc) << std::dec;
                        break;
                    case 'a':
                        out << "0x" << std::hex << (int) (EXTRACT_CJTYPE_IMM(l) + pc) << std::dec;
                        break;
                    case 'u':
                        out << "0x" << std::hex << (int) (EXTRACT_CITYPE_IMM(l) & (RISCV_BIGIMM_REACH - 1)) << std::dec;
                        break;
                    case '>':
                        out << "0x" << std::hex << (int) (EXTRACT_CITYPE_IMM(l) & 0x3f) << std::dec;
                        break;
                    case '<':
                        out << "0x%x" << std::hex << (int) (EXTRACT_CITYPE_IMM(l) & 0x1f) << std::dec;
                        break;
                    case 'T': /* Floating-point RS2.  */
                        out << riscv_fpr_names[EXTRACT_OPERAND(CRS2, l)];
                        break;
                    case 'D': /* Floating-point RS2 x8-x15.  */
                        out << riscv_fpr_names[EXTRACT_OPERAND(CRS2S, l) + 8];
                        break;
                }
                break;

            case 'V': /* RVV */
                switch (*++oparg) {
                    case 'd':
                    case 'f':
                        out << riscv_vecr_names_numeric[EXTRACT_OPERAND(VD, l)];
                        break;
                    case 'e':
                        if (!EXTRACT_OPERAND(VWD, l))
                            out << riscv_gpr_names[0];
                        else
                            out << riscv_vecr_names_numeric[EXTRACT_OPERAND(VD, l)];
                        break;
                    case 's':
                        out << riscv_vecr_names_numeric[EXTRACT_OPERAND(VS1, l)];
                        break;
                    case 't':
                    case 'u': /* VS1 == VS2 already verified at this point.  */
                    case 'v': /* VD == VS1 == VS2 already verified at this point.  */
                        out << riscv_vecr_names_numeric[EXTRACT_OPERAND(VS2, l)];
                        break;
                    case '0':
                        out << riscv_vecr_names_numeric[0];
                        break;
                    case 'b':
                    case 'c': {
                        int imm = (*oparg == 'b') ? EXTRACT_RVV_VB_IMM(l) : EXTRACT_RVV_VC_IMM(l);
                        unsigned int imm_vlmul = EXTRACT_OPERAND(VLMUL, imm);
                        unsigned int imm_vsew = EXTRACT_OPERAND(VSEW, imm);
                        unsigned int imm_vta = EXTRACT_OPERAND(VTA, imm);
                        unsigned int imm_vma = EXTRACT_OPERAND(VMA, imm);
                        unsigned int imm_vtype_res = (imm >> 8);

                        if (imm_vsew < ARRAY_SIZE(riscv_vsew) && imm_vlmul < ARRAY_SIZE(riscv_vlmul) &&
                            imm_vta < ARRAY_SIZE(riscv_vta) && imm_vma < ARRAY_SIZE(riscv_vma) && !imm_vtype_res &&
                            riscv_vsew[imm_vsew] != NULL && riscv_vlmul[imm_vlmul] != NULL)
                            out << riscv_vsew[imm_vsew] << ',' << riscv_vlmul[imm_vlmul] << ',' <<
                                riscv_vta[imm_vta] << ',' << riscv_vma[imm_vma];
                        else
                            out << imm;
                    } break;
                    case 'i':
                        out << (int) EXTRACT_RVV_VI_IMM(l);
                        break;
                    case 'j':
                        out << (int) EXTRACT_RVV_VI_UIMM(l);
                        break;
                    case 'k':
                        out << (int) EXTRACT_RVV_OFFSET(l);
                        break;
                    case 'm':
                        if (!EXTRACT_OPERAND(VMASK, l))
                            out << ',' << riscv_vecm_names_numeric[0];
                        break;
                }
                break;

            case ',':
            case '(':
            case ')':
            case '[':
            case ']':
                out << (char) *oparg;
                break;

            case '0':
                /* Only print constant 0 if it is the last argument.  */
                if (!oparg[1])
                    out << "0";
                break;

            case 'b':
            case 's':
                out << riscv_gpr_names[rs1];
                break;

            case 't':
                out << riscv_gpr_names[EXTRACT_OPERAND(RS2, l)];
                break;

            case 'u':
                out << "0x%" << std::hex << (unsigned) (EXTRACT_UTYPE_IMM(l) >> RISCV_IMM_BITS) << std::dec;
                break;

            case 'm':
                arg_print(EXTRACT_OPERAND(RM, l), riscv_rm, ARRAY_SIZE(riscv_rm), out);
                break;

            case 'P':
                arg_print(EXTRACT_OPERAND(PRED, l), riscv_pred_succ, ARRAY_SIZE(riscv_pred_succ), out);
                break;

            case 'Q':
                arg_print(EXTRACT_OPERAND(SUCC, l), riscv_pred_succ, ARRAY_SIZE(riscv_pred_succ), out);
                break;

            case 'o':
            case 'j':
                out << (int) EXTRACT_ITYPE_IMM(l);
                break;

            case 'q':
                out << (int) EXTRACT_STYPE_IMM(l);
                break;

            case 'f':
                out << (int) EXTRACT_STYPE_IMM(l);
                break;

            case 'a':
                out << "0x" << std::hex << EXTRACT_JTYPE_IMM(l) + pc << std::dec;
                break;

            case 'p':
                out << "0x" << std::hex << EXTRACT_BTYPE_IMM(l) + pc << std::dec;
                break;

            case 'd':
                out << riscv_gpr_names[rd];
                break;

            case 'y':
                out << "0x" << std::hex << (int) EXTRACT_OPERAND(BS, l) << std::dec;
                break;

            case 'z':
                out << riscv_gpr_names[0];
                break;

            case '>':
                out << "0x" << std::hex << (int) EXTRACT_OPERAND(SHAMT, l) << std::dec;
                break;

            case '<':
                out << "0x" << std::hex << (int) EXTRACT_OPERAND(SHAMTW, l) << std::dec;
                break;

            case 'S':
            case 'U':
                out << riscv_fpr_names[rs1];
                break;

            case 'T':
                out << riscv_fpr_names[EXTRACT_OPERAND(RS2, l)];
                break;

            case 'D':
                out << riscv_fpr_names[rd];
                break;

            case 'R':
                out << riscv_fpr_names[EXTRACT_OPERAND(RS3, l)];
                break;

            case 'E': {
				const char* csr_name = NULL;
				unsigned int csr = EXTRACT_OPERAND (CSR, l);
				switch (csr) {
#define DECLARE_CSR(name, num, a, b, c) case num: csr_name = #name; break;
#include "../opcode/riscv-opc.h"
#undef DECLARE_CSR
				}
				if (csr_name)
					out << csr_name;
				else
					out << "0x" << std::hex << csr << std::dec;
				break;
            }

            case 'Y':
                out << "0x" << std::hex << (int) EXTRACT_OPERAND(RNUM, l) << std::dec;
                break;

            case 'Z':
                out << rs1;
                break;

            default:
                /* xgettext:c-format */
                out << "# internal error, undefined modifier" << (char) *opargStart;
                return;
        }
    }
}

#if 0

static int
riscv_disassemble_insn (bfd_vma memaddr, insn_t word, disassemble_info *info)
{
  const struct riscv_opcode *op;
  static bool init = 0;
  static const struct riscv_opcode *riscv_hash[OP_MASK_OP + 1];
  struct riscv_private_data *pd;
  int insnlen;

#define OP_HASH_IDX(i) ((i) & (riscv_insn_length (i) == 2 ? 0x3 : OP_MASK_OP))

  /* Build a hash table to shorten the search time.  */
  if (! init)
    {
      for (op = riscv_opcodes; op->name; op++)
	if (!riscv_hash[OP_HASH_IDX (op->match)])
	  riscv_hash[OP_HASH_IDX (op->match)] = op;

      init = 1;
    }

  if (info->private_data == NULL)
    {
      int i;

      pd = info->private_data = xcalloc (1, sizeof (struct riscv_private_data));
      pd->gp = -1;
      pd->print_addr = -1;
      for (i = 0; i < (int)ARRAY_SIZE (pd->hi_addr); i++)
	pd->hi_addr[i] = -1;

      for (i = 0; i < info->symtab_size; i++)
	if (strcmp (bfd_asymbol_name (info->symtab[i]), RISCV_GP_SYMBOL) == 0)
	  pd->gp = bfd_asymbol_value (info->symtab[i]);
    }
  else
    pd = info->private_data;

  insnlen = riscv_insn_length (word);

  /* RISC-V instructions are always little-endian.  */
  info->endian_code = BFD_ENDIAN_LITTLE;

  info->bytes_per_chunk = insnlen % 4 == 0 ? 4 : 2;
  info->bytes_per_line = 8;
  /* We don't support constant pools, so this must be code.  */
  info->display_endian = info->endian_code;
  info->insn_info_valid = 1;
  info->branch_delay_insns = 0;
  info->data_size = 0;
  info->insn_type = dis_nonbranch;
  info->target = 0;
  info->target2 = 0;

  op = riscv_hash[OP_HASH_IDX (word)];
  if (op != NULL)
    {
      /* If XLEN is not known, get its value from the ELF class.  */
      if (info->mach == bfd_mach_riscv64)
	xlen = 64;
      else if (info->mach == bfd_mach_riscv32)
	xlen = 32;
      else if (info->section != NULL)
	{
	  Elf_Internal_Ehdr *ehdr = elf_elfheader (info->section->owner);
	  xlen = ehdr->e_ident[EI_CLASS] == ELFCLASS64 ? 64 : 32;
	}

      /* If arch has ZFINX flags, use gpr for disassemble.  */
      if(riscv_subset_supports (&riscv_rps_dis, "zfinx"))
	riscv_fpr_names = riscv_gpr_names_abi;

      for (; op->name; op++)
	{
	  /* Does the opcode match?  */
	  if (! (op->match_func) (op, word))
	    continue;
	  /* Is this a pseudo-instruction and may we print it as such?  */
	  if (no_aliases && (op->pinfo & INSN_ALIAS))
	    continue;
	  /* Is this instruction restricted to a certain value of XLEN?  */
	  if ((op->xlen_requirement != 0) && (op->xlen_requirement != xlen))
	    continue;

	  if (!riscv_multi_subset_supports (&riscv_rps_dis, op->insn_class))
	    continue;

	  /* It's a match.  */
	  (*info->fprintf_func) (info->stream, "%s", op->name);
	  print_insn_args (op->args, word, memaddr, info);

	  /* Try to disassemble multi-instruction addressing sequences.  */
	  if (pd->print_addr != (bfd_vma)-1)
	    {
	      info->target = pd->print_addr;
	      (*info->fprintf_func) (info->stream, " # ");
	      (*info->print_address_func) (info->target, info);
	      pd->print_addr = -1;
	    }

	  /* Finish filling out insn_info fields.  */
	  switch (op->pinfo & INSN_TYPE)
	    {
	    case INSN_BRANCH:
	      info->insn_type = dis_branch;
	      break;
	    case INSN_CONDBRANCH:
	      info->insn_type = dis_condbranch;
	      break;
	    case INSN_JSR:
	      info->insn_type = dis_jsr;
	      break;
	    case INSN_DREF:
	      info->insn_type = dis_dref;
	      break;
	    default:
	      break;
	    }

	  if (op->pinfo & INSN_DATA_SIZE)
	    {
	      int size = ((op->pinfo & INSN_DATA_SIZE)
			  >> INSN_DATA_SIZE_SHIFT);
	      info->data_size = 1 << (size - 1);
	    }

	  return insnlen;
	}
    }

  /* We did not find a match, so just print the instruction bits.  */
  info->insn_type = dis_noninsn;
  switch (insnlen)
    {
    case 2:
    case 4:
    case 8:
      (*info->fprintf_func) (info->stream, ".%dbyte\t0x%llx",
                             insnlen, (unsigned long long) word);
      break;
    default:
      {
        int i;
        (*info->fprintf_func) (info->stream, ".byte\t");
        for (i = 0; i < insnlen; ++i)
          {
            if (i > 0)
              (*info->fprintf_func) (info->stream, ", ");
            (*info->fprintf_func) (info->stream, "0x%02x",
                                   (unsigned int) (word & 0xff));
            word >>= 8;
          }
      }
      break;
    }
  return insnlen;
}
#endif

void riscv_dump_insn(uint64_t pc, uint64_t insn, std::ostream &out, const char *indent) {
    const struct riscv_opcode *op;
    out << indent;
    for (op = riscv_opcodes; op->name; op++) {
        if (! (op->match_func) (op, insn))
            continue;
        //if (op->pinfo & INSN_ALIAS)
            //continue;
        out << op->name;
        riscv_dump_insn_args(op->args, pc, insn, out);
        return;
    }
    out << insn;
}
