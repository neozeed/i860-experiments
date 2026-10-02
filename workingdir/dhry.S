gcc_compiled.:
.globl _Version
.data
_Version:
.byte "1.1",0
.text
	.align 4
.globl _main
	nop
_main:
	adds -16,sp,sp
	st.l fp,8(sp)
	st.l r1,12(sp)
	adds 8,sp,fp
	st.l r4,0(sp)
	mov r28,r4
	call _Proc0
	nop
	mov 0,r16
	call _exit
	nop
.L1:
	ld.l -8(fp),r4
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 16,sp,sp
.LC0:
.byte "DHRYSTONE PROGRAM, SOME STRING",0
.LC1:
.byte "DHRYSTONE PROGRAM, 1'ST STRING",0
.LC2:
.byte "DHRYSTONE PROGRAM, 2'ND STRING",0
	.align 4
.globl _Proc0
	nop
_Proc0:
	adds -144,sp,sp
	st.l fp,136(sp)
	st.l r1,140(sp)
	adds 136,sp,fp
	st.l r4,0(sp)
	st.l r5,4(sp)
	st.l r6,8(sp)
	mov r28,r4
	mov 48,r16
	call _malloc
	nop
	orh ha%_PtrGlbNext,r0,r31
	st.l r16,l%_PtrGlbNext(r31)
	mov 48,r16
	call _malloc
	nop
	orh ha%_PtrGlb,r0,r31
	st.l r16,l%_PtrGlb(r31)
	ld.l l%_PtrGlb(r31),r16
	orh ha%_PtrGlbNext,r0,r31
	ld.l l%_PtrGlbNext(r31),r20
	st.l r20,0(r16)
	orh ha%_PtrGlb,r0,r31
	ld.l l%_PtrGlb(r31),r16
	mov r16,r17
	addu 4,r16,r16
	st.l r0,0(r16)
	ld.l l%_PtrGlb(r31),r16
	mov r16,r17
	addu 8,r16,r16
	mov 2,r20
	st.l r20,0(r16)
	ld.l l%_PtrGlb(r31),r16
	mov r16,r17
	addu 12,r16,r16
	mov 40,r20
	st.l r20,0(r16)
	ld.l l%_PtrGlb(r31),r16
	addu 16,r16,r16
	mov r16,r16
	mov .LC0,r17
	call _strcpy
	nop
	addu -80,fp,r16
	mov r16,r16
	mov .LC1,r17
	call _strcpy
	nop
	mov 10,r20
	orh ha%_Array2Glob+1660,r0,r31
	st.l r20,l%_Array2Glob+1660(r31)
	mov 0,r5
.L3:
	mov 499999,r16
	subu r16,r5,r0
	bnc .L4
	call _Proc5
	nop
	call _Proc4
	nop
	mov fp,r16
	addu -8,fp,r16
	mov 2,r20
	st.l r20,0(r16)
	mov fp,r16
	addu -16,fp,r16
	mov 3,r20
	st.l r20,0(r16)
	addu -112,fp,r16
	mov r16,r16
	mov .LC2,r17
	call _strcpy
	nop
	mov fp,r16
	addu -48,fp,r16
	mov 1,r20
	st.l r20,0(r16)
	addu -80,fp,r16
	addu -112,fp,r17
	mov r16,r16
	mov r17,r17
	call _Func2
	nop
	mov r16,r17
	mov 0,r16
	xor 0,r17,r0
	bnc .L6
	mov 1,r16
.L6:
	orh ha%_BoolGlob,r0,r31
	st.l r16,l%_BoolGlob(r31)
.L7:
	mov fp,r16
	addu -8,fp,r16
	mov fp,r17
	addu -16,fp,r17
	ld.l 0(r16),r16
	ld.l 0(r17),r17
	subs r16,r17,r0
	bnc .L8
	mov fp,r16
	addu -24,fp,r16
	mov fp,r17
	addu -8,fp,r17
	ld.l 0(r17),r18
	shl 2,r18,r18
	ld.l 0(r17),r17
	addu r17,r18,r17
	mov fp,r18
	addu -16,fp,r18
	ld.l 0(r18),r18
	subu r17,r18,r17
	st.l r17,0(r16)
	mov fp,r16
	addu -8,fp,r16
	mov fp,r17
	addu -16,fp,r17
	addu -24,fp,r18
	ld.l 0(r16),r16
	ld.l 0(r17),r17
	mov r18,r18
	call _Proc7
	nop
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r17
	addu 1,r17,r17
	st.l r17,0(r16)
	br .L7
	nop
.L8:
	mov fp,r16
	addu -8,fp,r18
	mov fp,r16
	addu -24,fp,r19
	mov _Array1Glob,r16
	mov _Array2Glob,r17
	ld.l 0(r18),r18
	ld.l 0(r19),r19
	call _Proc8
	nop
	orh ha%_PtrGlb,r0,r31
	ld.l l%_PtrGlb(r31),r16
	call _Proc1
	nop
	mov fp,r16
	addu -40,fp,r16
	mov 65,r20
	st.b r20,0(r16)
.L9:
	mov fp,r16
	addu -40,fp,r16
	ld.b 0(r16),r16
	orh ha%_Char2Glob,r0,r31
	ld.b l%_Char2Glob(r31),r17
	subs r17,r16,r0
	bc .L10
	mov fp,r16
	addu -48,fp,r6
	mov fp,r16
	addu -40,fp,r16
	ld.b 0(r16),r16
	mov r16,r16
	mov 67,r17
	call _Func1
	nop
	mov r16,r16
	ld.l 0(r6),r17
	xor r16,r17,r0
	bnc .L12
	addu -48,fp,r17
	mov 0,r16
	mov r17,r17
	call _Proc6
	nop
.L12:
.L11:
	mov fp,r16
	addu -40,fp,r16
	ld.b 0(r16),r17
	addu 1,r17,r17
	st.b r17,0(r16)
	br .L9
	nop
.L10:
	mov fp,r16
	addu -24,fp,r16
	mov fp,r17
	addu -16,fp,r17
	mov fp,r18
	addu -8,fp,r18
	fld.l 0(r17),f8
	fld.l 0(r18),f12
	fmlow.dd f12,f8,f10
	fxfr f10,r17
	st.l r17,0(r16)
	mov fp,r16
	addu -16,fp,r6
	mov fp,r16
	addu -24,fp,r16
	mov fp,r17
	addu -8,fp,r17
	ld.l 0(r16),r16
	ld.l 0(r17),r17
	call .div
	nop
	mov r16,r16
	st.l r16,0(r6)
	mov fp,r16
	addu -16,fp,r16
	mov fp,r17
	addu -24,fp,r17
	mov fp,r18
	addu -16,fp,r18
	ld.l 0(r17),r17
	ld.l 0(r18),r18
	subu r17,r18,r17
	ixfr r17,f8
	mov 7,r20
	ixfr r20,f12
	fmlow.dd f12,f8,f10
	fxfr f10,r17
	mov fp,r18
	addu -8,fp,r18
	ld.l 0(r18),r18
	subu r17,r18,r17
	st.l r17,0(r16)
	addu -8,fp,r16
	mov r16,r16
	call _Proc2
	nop
.L5:
	addu 1,r5,r5
	br .L3
	nop
.L4:
.L2:
	ld.l -136(fp),r4
	ld.l -132(fp),r5
	ld.l -128(fp),r6
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 144,sp,sp
	.align 4
.globl _Proc1
	nop
_Proc1:
	adds -32,sp,sp
	st.l fp,24(sp)
	st.l r1,28(sp)
	adds 24,sp,fp
	st.l r4,0(sp)
	st.l r5,4(sp)
	st.l r6,8(sp)
	mov r28,r4
	mov fp,r5
	addu -8,fp,r6
	st.l r16,0(r6)
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	ld.l 0(r16),r16
	orh ha%_PtrGlb,r0,r31
	ld.l l%_PtrGlb(r31),r17
	mov r16,r16
	mov r17,r20
	mov 48,r17
	mov -4,r18
	bla r18,r17,.Lm0
	adds r16,r17,r19
.Lm0:
	adds r20,r17,r20
	adds r18,r17,r17
.Lm1:
	ld.l 0(r20),r31
	adds r18,r20,r20
	st.l r31,0(r19)
	bla r18,r17,.Lm1
	adds r18,r19,r19
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	mov r16,r17
	addu 12,r16,r16
	mov 5,r21
	st.l r21,0(r16)
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	ld.l 0(r16),r16
	mov r16,r17
	addu 12,r16,r16
	mov fp,r17
	addu -8,fp,r17
	ld.l 0(r17),r17
	mov r17,r18
	addu 12,r17,r17
	ld.l 0(r17),r21
	st.l r21,0(r16)
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	ld.l 0(r16),r16
	mov fp,r17
	addu -8,fp,r17
	ld.l 0(r17),r17
	ld.l 0(r17),r21
	st.l r21,0(r16)
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	ld.l 0(r16),r16
	ld.l 0(r16),r16
	call _Proc3
	nop
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	ld.l 0(r16),r16
	mov r16,r17
	addu 4,r16,r16
	ld.l 0(r16),r16
	xor 0,r16,r0
	bnc .L14
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	ld.l 0(r16),r16
	mov r16,r17
	addu 12,r16,r16
	mov 6,r21
	st.l r21,0(r16)
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	mov r16,r17
	addu 8,r16,r16
	mov fp,r17
	addu -8,fp,r17
	ld.l 0(r17),r17
	ld.l 0(r17),r17
	addu 8,r17,r17
	ld.l 0(r16),r16
	mov r17,r17
	call _Proc6
	nop
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	ld.l 0(r16),r16
	orh ha%_PtrGlb,r0,r31
	ld.l l%_PtrGlb(r31),r17
	ld.l 0(r17),r21
	st.l r21,0(r16)
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	ld.l 0(r16),r16
	mov r16,r17
	addu 12,r16,r16
	mov fp,r17
	addu -8,fp,r17
	ld.l 0(r17),r17
	ld.l 0(r17),r17
	addu 12,r17,r18
	ld.l 0(r16),r16
	mov 10,r17
	mov r18,r18
	call _Proc7
	nop
	br .L15
	nop
.L14:
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	mov fp,r17
	addu -8,fp,r17
	ld.l 0(r17),r17
	ld.l 0(r17),r17
	mov r16,r16
	mov r17,r20
	mov 48,r17
	mov -4,r18
	bla r18,r17,.Lm2
	adds r16,r17,r19
.Lm2:
	adds r20,r17,r20
	adds r18,r17,r17
.Lm3:
	ld.l 0(r20),r31
	adds r18,r20,r20
	st.l r31,0(r19)
	bla r18,r17,.Lm3
	adds r18,r19,r19
.L15:
.L13:
	ld.l -24(fp),r4
	ld.l -20(fp),r5
	ld.l -16(fp),r6
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 32,sp,sp
	.align 4
.globl _Proc2
	nop
_Proc2:
	adds -32,sp,sp
	st.l fp,24(sp)
	st.l r1,28(sp)
	adds 24,sp,fp
	mov r28,r17
	mov fp,r18
	addu -8,fp,r19
	st.l r16,0(r19)
	mov fp,r16
	addu -16,fp,r16
	mov fp,r20
	addu -8,fp,r20
	ld.l 0(r20),r20
	ld.l 0(r20),r20
	addu 10,r20,r20
	st.l r20,0(r16)
.L17:
	orh ha%_Char1Glob,r0,r31
	ld.b l%_Char1Glob(r31),r16
	mov 65,r20
	xor r20,r16,r0
	bnc .L20
	mov fp,r16
	addu -16,fp,r16
	ld.l 0(r16),r20
	addu -1,r20,r20
	st.l r20,0(r16)
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	mov fp,r20
	addu -16,fp,r20
	ld.l 0(r20),r20
	orh ha%_IntGlob,r0,r31
	ld.l l%_IntGlob(r31),r21
	subu r20,r21,r20
	st.l r20,0(r16)
	mov fp,r16
	addu -24,fp,r16
	st.l r0,0(r16)
.L20:
	mov fp,r16
	addu -24,fp,r16
	ld.l 0(r16),r16
	xor 0,r16,r0
	bnc .L21
	br .L18
	nop
.L21:
.L19:
	br .L17
	nop
.L18:
.L16:
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 32,sp,sp
	.align 4
.globl _Proc3
	nop
_Proc3:
	adds -32,sp,sp
	st.l fp,24(sp)
	st.l r1,28(sp)
	adds 24,sp,fp
	st.l r4,0(sp)
	st.l r5,4(sp)
	st.l r6,8(sp)
	mov r28,r4
	mov fp,r5
	addu -8,fp,r6
	st.l r16,0(r6)
	orh ha%_PtrGlb,r0,r31
	ld.l l%_PtrGlb(r31),r16
	xor 0,r16,r0
	bc .L23
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	ld.l l%_PtrGlb(r31),r17
	ld.l 0(r17),r19
	st.l r19,0(r16)
	br .L24
	nop
.L23:
	mov 100,r19
	orh ha%_IntGlob,r0,r31
	st.l r19,l%_IntGlob(r31)
.L24:
	orh ha%_PtrGlb,r0,r31
	ld.l l%_PtrGlb(r31),r16
	addu 12,r16,r18
	mov 10,r16
	orh ha%_IntGlob,r0,r31
	ld.l l%_IntGlob(r31),r17
	mov r18,r18
	call _Proc7
	nop
.L22:
	ld.l -24(fp),r4
	ld.l -20(fp),r5
	ld.l -16(fp),r6
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 32,sp,sp
	.align 4
.globl _Proc4
	nop
_Proc4:
	adds -16,sp,sp
	st.l fp,8(sp)
	st.l r1,12(sp)
	adds 8,sp,fp
	mov r28,r16
	mov fp,r17
	addu -8,fp,r17
	mov 0,r18
	orh ha%_Char1Glob,r0,r31
	ld.b l%_Char1Glob(r31),r19
	mov 65,r20
	xor r20,r19,r0
	bnc .L26
	mov 1,r18
.L26:
	st.l r18,0(r17)
	mov fp,r17
	addu -8,fp,r17
	mov fp,r18
	addu -8,fp,r18
	ld.l 0(r18),r18
	orh ha%_BoolGlob,r0,r31
	ld.l l%_BoolGlob(r31),r19
	or r19,r18,r18
	st.l r18,0(r17)
	mov 66,r21
	orh ha%_Char2Glob,r0,r31
	st.b r21,l%_Char2Glob(r31)
.L25:
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 16,sp,sp
	.align 4
.globl _Proc5
	nop
_Proc5:
	adds -16,sp,sp
	st.l fp,8(sp)
	st.l r1,12(sp)
	adds 8,sp,fp
	mov r28,r16
	mov 65,r17
	orh ha%_Char1Glob,r0,r31
	st.b r17,l%_Char1Glob(r31)
	orh ha%_BoolGlob,r0,r31
	st.l r0,l%_BoolGlob(r31)
.L27:
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 16,sp,sp
	.align 4
.globl _Proc6
	nop
_Proc6:
	adds -48,sp,sp
	st.l fp,40(sp)
	st.l r1,44(sp)
	adds 40,sp,fp
	st.l r4,0(sp)
	st.l r5,4(sp)
	st.l r6,8(sp)
	st.l r7,12(sp)
	st.l r8,16(sp)
	mov r28,r4
	mov fp,r5
	addu -8,fp,r6
	st.l r16,0(r6)
	mov fp,r7
	addu -16,fp,r8
	st.l r17,0(r8)
	mov fp,r16
	addu -16,fp,r16
	ld.l 0(r16),r16
	mov fp,r17
	addu -8,fp,r17
	ld.l 0(r17),r18
	st.l r18,0(r16)
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	call _Func3
	nop
	mov r16,r16
	xor 0,r16,r0
	bnc .L29
	mov fp,r16
	addu -16,fp,r16
	ld.l 0(r16),r16
	mov 3,r18
	st.l r18,0(r16)
.L29:
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	addu 0,r16,r16
	subu 4,r16,r0
	bnc .L39
	shl 2,r16,r16
	mov .L38,r17
	addu r17,r16,r16
	ld.l 0(r16),r16
	bri r16
	nop
.data
	.align 4
.L38:
	.long .L31
	.long .L32
	.long .L35
	.long .L36
	.long .L37
.text
.L31:
	mov fp,r16
	addu -16,fp,r16
	ld.l 0(r16),r16
	st.l r0,0(r16)
	br .L30
	nop
.L32:
	orh ha%_IntGlob,r0,r31
	ld.l l%_IntGlob(r31),r16
	subs 100,r16,r0
	bnc .L33
	mov fp,r16
	addu -16,fp,r16
	ld.l 0(r16),r16
	st.l r0,0(r16)
	br .L34
	nop
.L33:
	mov fp,r16
	addu -16,fp,r16
	ld.l 0(r16),r16
	mov 3,r18
	st.l r18,0(r16)
.L34:
	br .L30
	nop
.L35:
	mov fp,r16
	addu -16,fp,r16
	ld.l 0(r16),r16
	mov 1,r18
	st.l r18,0(r16)
	br .L30
	nop
.L36:
	br .L30
	nop
.L37:
	mov fp,r16
	addu -16,fp,r16
	ld.l 0(r16),r16
	mov 2,r18
	st.l r18,0(r16)
.L39:
.L30:
.L28:
	ld.l -40(fp),r4
	ld.l -36(fp),r5
	ld.l -32(fp),r6
	ld.l -28(fp),r7
	ld.l -24(fp),r8
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 48,sp,sp
	.align 4
.globl _Proc7
	nop
_Proc7:
	adds -48,sp,sp
	st.l fp,40(sp)
	st.l r1,44(sp)
	adds 40,sp,fp
	mov r28,r19
	mov fp,r20
	addu -8,fp,r21
	st.l r16,0(r21)
	mov fp,r16
	addu -16,fp,r22
	st.l r17,0(r22)
	mov fp,r17
	addu -24,fp,r23
	st.l r18,0(r23)
	mov fp,r18
	addu -32,fp,r18
	mov fp,r24
	addu -8,fp,r24
	ld.l 0(r24),r24
	addu 2,r24,r24
	st.l r24,0(r18)
	mov fp,r18
	addu -24,fp,r18
	ld.l 0(r18),r18
	mov fp,r24
	addu -16,fp,r24
	mov fp,r25
	addu -32,fp,r25
	ld.l 0(r24),r24
	ld.l 0(r25),r25
	addu r25,r24,r24
	st.l r24,0(r18)
.L40:
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 48,sp,sp
	.align 4
.globl _Proc8
	nop
_Proc8:
	adds -64,sp,sp
	st.l fp,56(sp)
	st.l r1,60(sp)
	adds 56,sp,fp
	mov r28,r20
	mov fp,r21
	addu -8,fp,r22
	st.l r16,0(r22)
	mov fp,r16
	addu -16,fp,r23
	st.l r17,0(r23)
	mov fp,r17
	addu -24,fp,r24
	st.l r18,0(r24)
	mov fp,r18
	addu -32,fp,r25
	st.l r19,0(r25)
	mov fp,r19
	addu -40,fp,r19
	mov fp,r26
	addu -24,fp,r26
	ld.l 0(r26),r26
	addu 5,r26,r26
	st.l r26,0(r19)
	mov fp,r19
	addu -8,fp,r19
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r26
	shl 2,r26,r26
	ld.l 0(r19),r19
	addu r19,r26,r19
	mov fp,r26
	addu -32,fp,r26
	ld.l 0(r26),r29
	st.l r29,0(r19)
	mov fp,r19
	addu -8,fp,r19
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r26
	shl 2,r26,r26
	ld.l 0(r19),r19
	addu r19,r26,r19
	mov r19,r26
	addu 4,r19,r19
	mov fp,r26
	addu -8,fp,r26
	mov fp,r27
	addu -40,fp,r27
	ld.l 0(r27),r27
	shl 2,r27,r27
	ld.l 0(r26),r26
	addu r26,r27,r26
	ld.l 0(r26),r29
	st.l r29,0(r19)
	mov fp,r19
	addu -8,fp,r19
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r26
	shl 2,r26,r26
	ld.l 0(r19),r19
	addu r19,r26,r19
	mov r19,r26
	addu 120,r19,r19
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r29
	st.l r29,0(r19)
	mov fp,r19
	addu -48,fp,r19
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r29
	st.l r29,0(r19)
.L42:
	mov fp,r19
	addu -48,fp,r19
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r26
	addu 1,r26,r26
	ld.l 0(r19),r19
	subs r26,r19,r0
	bc .L43
	mov fp,r19
	addu -16,fp,r19
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r27
	mov fp,r26
	addu -48,fp,r26
	ld.l 0(r26),r26
	shl 2,r26,r26
	ixfr r27,f8
	mov 204,r29
	ixfr r29,f12
	fmlow.dd f12,f8,f10
	fxfr f10,r27
	ld.l 0(r19),r19
	addu r19,r27,r19
	addu r19,r26,r19
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r29
	st.l r29,0(r19)
.L44:
	mov fp,r19
	addu -48,fp,r19
	ld.l 0(r19),r26
	addu 1,r26,r26
	st.l r26,0(r19)
	br .L42
	nop
.L43:
	mov fp,r19
	addu -16,fp,r19
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r27
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r26
	ixfr r27,f8
	mov 204,r29
	ixfr r29,f12
	fmlow.dd f12,f8,f10
	fxfr f10,r27
	ld.l 0(r19),r19
	addu r19,r27,r19
	shl 2,r26,r26
	addu r19,r26,r19
	mov r19,r26
	addu -4,r19,r19
	ld.l 0(r19),r26
	addu 1,r26,r26
	st.l r26,0(r19)
	mov fp,r19
	addu -16,fp,r19
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r27
	mov fp,r26
	addu -40,fp,r26
	ld.l 0(r26),r26
	shl 2,r26,r26
	ixfr r27,f8
	mov 204,r29
	ixfr r29,f12
	fmlow.dd f12,f8,f10
	fxfr f10,r27
	ld.l 0(r19),r19
	addu r19,r27,r19
	addu r26,r19,r19
	mov r19,r26
	addu 4080,r19,r19
	mov fp,r26
	addu -8,fp,r26
	mov fp,r27
	addu -40,fp,r27
	ld.l 0(r27),r27
	shl 2,r27,r27
	ld.l 0(r26),r26
	addu r26,r27,r26
	ld.l 0(r26),r29
	st.l r29,0(r19)
	mov 5,r29
	orh ha%_IntGlob,r0,r31
	st.l r29,l%_IntGlob(r31)
.L41:
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 64,sp,sp
	.align 4
.globl _Func1
	nop
_Func1:
	adds -48,sp,sp
	st.l fp,40(sp)
	st.l r1,44(sp)
	adds 40,sp,fp
	mov r28,r18
	mov fp,r19
	addu -8,fp,r20
	st.b r16,0(r20)
	mov fp,r21
	addu -16,fp,r22
	st.b r17,0(r22)
	mov fp,r16
	addu -24,fp,r16
	mov fp,r17
	addu -8,fp,r17
	ld.b 0(r17),r23
	st.b r23,0(r16)
	mov fp,r16
	addu -32,fp,r16
	mov fp,r17
	addu -24,fp,r17
	ld.b 0(r17),r23
	st.b r23,0(r16)
	mov fp,r16
	addu -32,fp,r16
	mov fp,r17
	addu -16,fp,r17
	ld.b 0(r16),r16
	ld.b 0(r17),r17
	xor r17,r16,r0
	bc .L46
	mov 0,r16
	br .L45
	nop
	br .L47
	nop
.L46:
	mov 1,r16
	br .L45
	nop
.L47:
.L45:
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 48,sp,sp
	.align 4
.globl _Func2
	nop
_Func2:
	adds -64,sp,sp
	st.l fp,56(sp)
	st.l r1,60(sp)
	adds 56,sp,fp
	st.l r4,0(sp)
	st.l r5,4(sp)
	st.l r6,8(sp)
	st.l r7,12(sp)
	st.l r8,16(sp)
	mov r28,r4
	mov fp,r5
	addu -8,fp,r6
	st.l r16,0(r6)
	mov fp,r7
	addu -16,fp,r8
	st.l r17,0(r8)
	mov fp,r16
	addu -24,fp,r16
	mov 1,r19
	st.l r19,0(r16)
.L49:
	mov fp,r16
	addu -24,fp,r16
	ld.l 0(r16),r16
	subs 1,r16,r0
	bc .L50
	mov fp,r16
	addu -8,fp,r16
	mov fp,r17
	addu -24,fp,r17
	ld.l 0(r16),r16
	ld.l 0(r17),r17
	addu r17,r16,r16
	ld.b 0(r16),r16
	mov fp,r17
	addu -16,fp,r17
	mov fp,r18
	addu -24,fp,r18
	ld.l 0(r18),r18
	ld.l 0(r17),r17
	addu r17,r18,r17
	ld.b 1(r17),r17
	mov r16,r16
	mov r17,r17
	call _Func1
	nop
	mov r16,r16
	xor 0,r16,r0
	bnc .L51
	mov fp,r16
	addu -32,fp,r16
	mov 65,r19
	st.b r19,0(r16)
	mov fp,r16
	addu -24,fp,r16
	ld.l 0(r16),r17
	addu 1,r17,r17
	st.l r17,0(r16)
.L51:
	br .L49
	nop
.L50:
	mov fp,r16
	addu -32,fp,r16
	ld.b 0(r16),r16
	mov 86,r17
	subs r17,r16,r0
	bnc .L52
	mov fp,r16
	addu -32,fp,r16
	ld.b 0(r16),r16
	mov 90,r17
	subs r17,r16,r0
	bc .L52
	mov fp,r16
	addu -24,fp,r16
	mov 7,r19
	st.l r19,0(r16)
.L52:
	mov fp,r16
	addu -32,fp,r16
	ld.b 0(r16),r16
	mov 88,r17
	xor r17,r16,r0
	bnc .L53
	mov 1,r16
	br .L48
	nop
	br .L54
	nop
.L53:
	mov fp,r16
	addu -8,fp,r16
	mov fp,r17
	addu -16,fp,r17
	ld.l 0(r16),r16
	ld.l 0(r17),r17
	call _strcmp
	nop
	mov r16,r16
	subs 0,r16,r0
	bnc .L55
	mov fp,r16
	addu -24,fp,r16
	mov fp,r17
	addu -24,fp,r17
	ld.l 0(r17),r17
	addu 7,r17,r17
	st.l r17,0(r16)
	mov 1,r16
	br .L48
	nop
	br .L56
	nop
.L55:
	mov 0,r16
	br .L48
	nop
.L56:
.L54:
.L48:
	ld.l -56(fp),r4
	ld.l -52(fp),r5
	ld.l -48(fp),r6
	ld.l -44(fp),r7
	ld.l -40(fp),r8
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 64,sp,sp
	.align 4
.globl _Func3
	nop
_Func3:
	adds -32,sp,sp
	st.l fp,24(sp)
	st.l r1,28(sp)
	adds 24,sp,fp
	mov r28,r17
	mov fp,r18
	addu -8,fp,r19
	st.l r16,0(r19)
	mov fp,r16
	addu -16,fp,r16
	mov fp,r20
	addu -8,fp,r20
	ld.l 0(r20),r21
	st.l r21,0(r16)
	mov fp,r16
	addu -16,fp,r16
	ld.l 0(r16),r16
	xor 2,r16,r0
	bnc .L58
	mov 1,r16
	br .L57
	nop
.L58:
	mov 0,r16
	br .L57
	nop
.L57:
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 32,sp,sp
.comm _PtrGlbNext,8
.comm _PtrGlb,8
.comm _Array2Glob,10408
.comm _Array1Glob,208
.comm _Char2Glob,8
.comm _Char1Glob,8
.comm _BoolGlob,8
.comm _IntGlob,8
