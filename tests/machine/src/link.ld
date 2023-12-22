OUTPUT_ARCH( "riscv" )
ENTRY(_start)

SECTIONS
{
  .tohost 0x40008000 (NOLOAD): { *(.tohost) }
  . = 0x80000000;
  .text.init : { *(.text.init) }
  . = ALIGN(0x1000);
  .text : { *(.text) }
  . = ALIGN(0x1000);
  .data : { *(.data) }
  .bss : { *(.bss) }
  _end = .;
}

