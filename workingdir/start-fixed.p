        .text
        .align  4
        .globl  _start

_start:
         
        mov     1071,r16
        mov     462,r17

        call    _gcd
        nop

         
        mov     21,r17
        xor     r16,r17,r0
        bnc     .Lfail
        nop

         
        mov     1,r16
        orh     h%passmsg,r0,r17
        or      l%passmsg,r17,r17
        mov     18,r18
        mov     4,r31
        trap    r31,r31,r0

         
        mov     0,r16
        mov     1,r31
        trap    r31,r31,r0

.Lfail:
         
        mov     1,r16
        orh     h%failmsg,r0,r17
        or      l%failmsg,r17,r17
        mov     18,r18
        mov     4,r31
        trap    r31,r31,r0

        mov     1,r16
        mov     1,r31
        trap    r31,r31,r0

        .data
        .align 4

passmsg:
        .byte 71,67,67,32,105,56,54,48,32,71,67,68,32,80,65,83,83,10

failmsg:
        .byte 71,67,67,32,105,56,54,48,32,71,67,68,32,70,65,73,76,10
