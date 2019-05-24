#include <pma-defines.h>

.section .text.init;
.align 2;
.global _start;
_start:

	li t0, PMA_RAM_START_DEF; // converted to 2 instructions addiw and slli
	csrr a0, mhartid;
	jr t0;
