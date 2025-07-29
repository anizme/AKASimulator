/*
 * Linker script for STM32F103C8T6
 * Flash: 64KB at 0x08000000
 * SRAM: 20KB at 0x20000000
 */

ENTRY(Reset_Handler)

MEMORY
{
    FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 64K
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 20K
}

SECTIONS
{
    /* Interrupt vector table */
    .isr_vector :
    {
        . = ALIGN(4);
        KEEP(*(.isr_vector))
        . = ALIGN(4);
    } > FLASH

    /* Readonly instructions and data */
    .text :
    {
        . = ALIGN(4);
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
        _etext = .;
    } > FLASH

    /* Initialized data */
    .data : ALIGN(4)
    {
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > SRAM AT > FLASH

    /* Address of .data in Flash */
    _sidata = LOADADDR(.data);

    /* Declared but uninitialized data */
    .bss : ALIGN(4)
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > SRAM

    /* SP to last of SRAM */
    _estack = ORIGIN(SRAM) + LENGTH(SRAM);

    /* Remove tobe unused sections */
    /DISCARD/ :
    {
        *(.ARM.attributes)
        *(.comment)
        *(.debug*)
    }
}
