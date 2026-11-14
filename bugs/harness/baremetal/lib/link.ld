/* Bare-metal guest layout: everything in RAM starting at 0x80000000 (AR_RAM_START). Use a RAM length of at
 * least 2 MiB (the configurations of bugs/harness/configs use 64 MiB). */
OUTPUT_ARCH("riscv")
ENTRY(_start)
SECTIONS
{
  . = 0x80000000;
  .text.init : { *(.text.init) }
  .text : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.* .srodata .srodata.*) }
  .data : { *(.data .data.* .sdata .sdata.*) }
  . = ALIGN(8);
  __bss_start = .;
  .bss : { *(.bss .bss.* .sbss .sbss.* COMMON) }
  . = ALIGN(8);
  __bss_end = .;
  . = ALIGN(16);
  . = . + 0x40000;
  __stack_top = .;
  _end = .;
}
