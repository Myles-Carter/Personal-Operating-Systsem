/* linker.ld - simple RISC-V kernel linker script for QEMU virt */

OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY
{
  RAM (rwx) : ORIGIN = 0x80200000, LENGTH = 128M
}

SECTIONS
{
  . = ORIGIN(RAM);

  .text : {
    KEEP(*(.text.entry))
    *(.text*)
  } > RAM

  .rodata : {
    *(.rodata*)
  } > RAM

  .data : {
    *(.data*)
  } > RAM

  .bss : {
    __bss_start = .;
    *(.bss*)
    *(COMMON)
    __bss_end = .;
  } > RAM

  /* simple kernel stack for boot CPU */
  . = ALIGN(16);
  . += 0x4000;      /* 16 KiB stack */
  _stack_top = .;
}
