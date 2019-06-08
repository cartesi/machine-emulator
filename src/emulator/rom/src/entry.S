#include <pma-defines.h>
#include "rom-defines.h"

// Define HTIF's tohost and fromhost
.section .tohost
.align 3;
.global tohost; tohost: .quad 0;
.global fromhost; fromhost: .quad 0;

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
	li gp, imm; \
	j exit;

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
	// Set the exception handler to trap
	// This is just in case an exception happens
	la t0, trap;
	csrw mtvec, t0;

	// Calls ROM initialization.
	li a0, PMA_START_DEF;
	li a1, PMA_EXT_START_DEF;
	ld t0, 0(a0);   // RAM start addr
	ld t1, 8(a0);   // RAM length
	srl t0, t0, 12; // clear reserved bits
	sll t0, t0, 12; // clear reserved bits
	srl t1, t1, 12; // clear reserved bits
	sll t1, t1, 12; // clear reserved bits
	add t3, t0, t1; // Calc RAM end addr
	bltu t3, t0, error; // check overflow
	li a3, DEVICE_TREE_MAX_SIZE;  // Reserving 64KiB for device tree
	sub a2, t3, a3;
	mv sp, a2;     // Set stack pointer to end of RAM - 64KiB
	csrr a4, misa;
	call rom_init; // Expects the return value to be at a0
	beqz a0, error;
	mv a1, a0;
	csrr a0, mhartid;
	jr t0; // jump to RAM start

error:
	exit_imm(1);


// The exception handler simply copies the cause to register
// gp and falls through to exit
trap:
	csrr gp, mcause;

// Exits via HTIF using gp content as the exit code
exit:
	// HTIF exits with dev = cmd = 0 and a payload with lsb set.
	// the exit code is taken from payload >> 2
	slli gp, gp, 16;
	srli gp, gp, 15;
	ori gp, gp, 1;
1:
	li t0, PMA_HTIF_START_DEF
	sd gp, 0(t0);
	j 1b; // Should not be necessary
