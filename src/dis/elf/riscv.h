/* RISC-V ELF support for BFD.
   Copyright (C) 2011-2022 Free Software Foundation, Inc.

   Contributed by Andrew Waterman (andrew@sifive.com).
   Based on MIPS ELF support for BFD, by Ian Lance Taylor.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

/* This file holds definitions specific to the RISCV ELF ABI.  Note
   that most of this is not actually implemented by BFD.  */

#ifndef _ELF_RISCV_H
#define _ELF_RISCV_H

/* Processor specific flags for the ELF header e_flags field.  */

/* File may contain compressed instructions.  */
#define EF_RISCV_RVC 0x0001

/* Which floating-point ABI a file uses.  */
#define EF_RISCV_FLOAT_ABI 0x0006

/* File uses the soft-float ABI.  */
#define EF_RISCV_FLOAT_ABI_SOFT 0x0000

/* File uses the single-float ABI.  */
#define EF_RISCV_FLOAT_ABI_SINGLE 0x0002

/* File uses the double-float ABI.  */
#define EF_RISCV_FLOAT_ABI_DOUBLE 0x0004

/* File uses the quad-float ABI.  */
#define EF_RISCV_FLOAT_ABI_QUAD 0x0006

/* File uses the 32E base integer instruction.  */
#define EF_RISCV_RVE 0x0008

/* The name of the global pointer symbol.  */
#define RISCV_GP_SYMBOL "__global_pointer$"

/* Processor specific dynamic array tags.  */
#define DT_RISCV_VARIANT_CC (DT_LOPROC + 1)

/* RISC-V specific values for st_other.  */
#define STO_RISCV_VARIANT_CC 0x80

/* Additional section types.  */
#define SHT_RISCV_ATTRIBUTES 0x70000003 /* Section holds attributes.  */

/* Processor specific program header types.  */

/* Location of RISC-V ELF attribute section. */
#define PT_RISCV_ATTRIBUTES 0x70000003

/* Object attributes.  */
enum
{
  /* 0-3 are generic.  */
  Tag_RISCV_stack_align = 4,
  Tag_RISCV_arch = 5,
  Tag_RISCV_unaligned_access = 6,
  Tag_RISCV_priv_spec = 8,
  Tag_RISCV_priv_spec_minor = 10,
  Tag_RISCV_priv_spec_revision = 12
};

#endif /* _ELF_RISCV_H */
