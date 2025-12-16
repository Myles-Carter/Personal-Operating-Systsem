/* start.S - RISC-V entry for QEMU virt */
/* Build target: rv64 (LP64) */

.section .text.entry
.globl _start
.extern kmain
.extern __bss_start
.extern __bss_end
.extern _stack_top

_start:
    /* setup stack pointer */
    la      sp, _stack_top

    /* clear .bss */
    la      t0, __bss_start
    la      t1, __bss_end
1:
    bge     t0, t1, 2f
    sd      zero, 0(t0)
    addi    t0, t0, 8
    j       1b
2:
    /* call C kernel */
    call    kmain

    /* if kmain returns, just idle forever */
3:
    wfi
    j       3b
