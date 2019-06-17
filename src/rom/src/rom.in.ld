OUTPUT_ARCH( "riscv" )
ENTRY(_start)

#include <pma-defines.h>

SECTIONS
{
  .tohost PMA_HTIF_START_DEF (NOLOAD): { *(.tohost) }
  . = 0x1000;
  .text.init : { *(.text.init) }
  . = ALIGN(0x1000);
  .text : { *(.text) }
  . = ALIGN(0x1000);
  .data : { *(.data) }
  .bss : { *(.bss) }
  _end = .;
}
