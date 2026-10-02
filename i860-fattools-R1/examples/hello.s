        .text
        .globl  _start
_start:
        orh     h%tty_name,r0,r16
        or      l%tty_name,r16,r16
        or      1,r0,r17
        or      0,r0,r18
        or      5,r0,r31
        trap    r31,r31,r0
        mov     r16,r20

        mov     r20,r16
        orh     h%message,r0,r17
        or      l%message,r17,r17
        or      13,r0,r18
        or      4,r0,r31
        trap    r31,r31,r0

        mov     r20,r16
        or      6,r0,r31
        trap    r31,r31,r0

        or      0,r0,r16
        or      1,r0,r31
        trap    r31,r31,r0

        .data
        .align  4
tty_name:
        .byte   47,100,101,118,47,116,116,121,0
message:
        .byte   104,105,32,102,114,111,109,32,105,56,54,48,10
