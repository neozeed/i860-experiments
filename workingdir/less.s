gcc_compiled.:
.text
	.align 4
.globl _less
	nop
_less:
	adds -32,sp,sp
	st.l fp,24(sp)
	st.l r1,28(sp)
	adds 24,sp,fp
	mov r28,r18
	mov fp,r19
	addu -8,fp,r20
	st.l r16,0(r20)
	mov fp,r21
	addu -16,fp,r22
	st.l r17,0(r22)
	mov 0,r16
	mov fp,r17
	addu -8,fp,r17
	mov fp,r23
	addu -16,fp,r23
	ld.l 0(r17),r17
	ld.l 0(r23),r23
	subu r17,r23,r0
	bc .L2
	mov 1,r16
.L2:
	mov r16,r16
	br .L1
	nop
.L1:
	ld.l 4(fp),r1
	ld.l 0(fp),fp
	bri r1
	addu 32,sp,sp
