#include <pma-defines.h>

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

	// Test SD PMA address overflow
	// sp starts at zero
	// this should trigger and exception
	addi sp,sp,-16;
	sd s0,8(sp);

	// fallback if exception was not triggered
	exit_imm(1);

// catch exception and exit
trap:
	exit_imm(0);

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
