// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//


#include <pma-defines.h>
#include <uarch-defines.h>

// entry point of the code executed on the microarchitecture's ROM

.section .text.init;
.align 8;
.global _start;

// This label is located at physical address PMA_UARCH_RAM_START_DEF
// This is the first address executed by the micro emulator
_start:
  
  // Stack initialization
  li sp, PMA_UARCH_RAM_START_DEF  
  li t0, PMA_UARCH_RAM_LENGTH_DEF
  add sp, sp, t0

  // Copy micro emulator code from uROM to uRAM
  li a0, PMA_UARCH_RAM_START_DEF                 // a0 = destination address
  la a1, _binary_uarch_run_bin_start  // a1 = source  address
  la a2, _binary_uarch_run_bin_end    // a2 = size
  sub a2, a2, a1
  call memcpy

  // execute uarch_run() that was copied to the beginning of uRAM by the previous memcpy 
  li t0, PMA_UARCH_RAM_START_DEF
  jalr ra, 0(t0) // call uarch_run()
  // Execution resumes here, when uarch_run() returns


  // Restore uRAM to pristine state by filling it with zeros.
  // We can't use the "C" memset() because it uses the stack, in RAM, to store arguments and locals.`
  li a0, PMA_UARCH_RAM_START_DEF   // destination
  li a1, 0                    // zero memory
  li a2, PMA_UARCH_RAM_LENGTH_DEF  // size
  call zero_memory

  // Restore register to pristine state
  li x1, 0
  li x2, 0
  li x3, 0
  li x4, 0
  li x5, 0
  li x6, 0
  li x7, 0
  li x8, 0
  li x9, 0
  li x10, 0
  li x11, 0
  li x12, 0
  li x13, 0
  li x14, 0
  li x15, 0
  li x16, 0
  li x17, 0
  li x18, 0
  li x19, 0
  li x20, 0
  li x21, 0
  li x22, 0
  li x23, 0
  li x24, 0
  li x25, 0
  li x26, 0
  li x27, 0
  li x28, 0
  li x29, 0
  li x30, 0
  li x31, 0
  
  // Halt by jumping to uROM start
  // The micro interpreter (uinterpret) halts after processing a jump to the begining of uROM
  jal x0, _start
  

// Fills a memory range with zeros
// Arguments passed in registers:
// a0 - start address
// a2 - length
 zero_memory:  
  li t0, 8
  blt a2, t0, 1f   // branch if remaining size is < 8
  sd x0, 0(a0)     // update 8 bytes
  addi a0, a0, 8   // advance address by 8
  addi a2, a2, -8  // subtract 8 from size 
  j zero_memory
1: 
  beqz a2, 2f       // branch if remaining size is zero
  sb x0, 0(a0)      // update 1 byte.      
  addi a0, a0, 1    // advance memory by 1
  addi a2, a2, -1   // subtract 1 from size
  j 1b
2:
  ret
