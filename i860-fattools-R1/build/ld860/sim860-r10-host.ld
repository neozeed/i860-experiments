SECTIONS { . = 0x00401000; .text : { *(.text*) *(.rodata*) } . = 0x00405000; .data : { *(.data*) *(.bss*) *(COMMON) } /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.got*) } }
