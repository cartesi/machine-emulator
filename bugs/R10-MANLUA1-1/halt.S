# Bare-metal guest: issue one HTIF halt request (DEV=HALT=0, CMD=HALT=0, DATA=1) and spin.
# If the request is ignored, the guest keeps spinning and the machine keeps executing.
.section .text.init
.globl _start
_start:
    li t0, 0x40008000      # HTIF tohost
    li t1, 1               # DEV=0, CMD=0, DATA bit 0 = 1
    sd t1, 0(t0)
1:  j 1b
