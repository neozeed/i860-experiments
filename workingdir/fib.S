gcc_compiled.:
.text
.LC0:
.byte "%d",10,0
	.align 4
.globl _main
	nop
_main:
	adds -48,sp,sp
	st.l fp,40(sp)
	st.l r1,44(sp)
	adds 40,sp,fp
	st.l r4,0(sp)
	mov r28,r4
	mov fp,r16
	addu -24,fp,r16
	st.l r0,0(r16)
.L2:
	mov fp,r16
	addu -24,fp,r16
	ld.l 0(r16),r16
	subs 255,r16,r0
	bc .L3
	mov fp,r16
	addu -8,fp,r16
	st.l r0,0(r16)
	mov fp,r16
	addu -16,fp,r16
	mov 1,r19
	st.l r19,0(r16)
.L4:
	mov fp,r16
	addu -8,fp,r17
	mov .LC0,r16
	ld.l 0(r17),r17
	call _printf
	nop
	mov fp,r16
	addu -24,fp,r16
	mov fp,r17
	addu -8,fp,r17
	mov fp,r18
	addu -16,fp,r18
	ld.l 0(r17),r17
	ld.l 0(r18),r18
	addu r18,r17,r17
	st.l r17,0(r16)
	mov fp,r16
	addu -8,fp,r16
	mov fp,r17
	addu -16,fp,r17
	ld.l 0(r17),r19
	st.l r19,0(r16)
	mov fp,r16
	addu -16,fp,r16
	mov fp,r17
	addu -24,fp,r17
	ld.l 0(r17),r19
	st.l r19,0(r16)
.L6:
	mov fp,r16
	addu -8,fp,r16
	ld.l 0(r16),r16
	subs 256,r16,r0
	bc .L5
	br .L4
	nop
.L5:
	br .L2
	nop
.L3:
.L1:
	ld.l -40(fp),r4
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 48,sp,sp
