    .section .text.init
    .globl _start
_start:
    li   sp, 0x80400000            # top of the 4 MiB RAM
    call main
1:  j    1b
