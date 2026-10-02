# 1 ""
	.file	"u.c"
	.version	"01.01"
# PGC Rel 2.0a -opt 1
	.text
	.align	4
	.long	.EN1-__umodsi3+0xc8000000
	.globl	__umodsi3
	.align	8
__umodsi3:
	.set .a1, 80
	.set .f1, 32
	orh [.STACK+.f1-16]@h, %r0, %r28
	or [.STACK+.f1-16]@l, %r28, %r28
	st.l %r1, 4(%r28)
                                              
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
	
	
	
	
	
	
	st.l %r16, 48(%r28)
	st.l %r17, 52(%r28)
.EN1:
# lineno: 11
	ld.l 48(%r28), %r16
	call mth_i_uimod
	ld.l 52(%r28), %r17
# lineno: 12
	
	
	
	
	ld.l 4(%r28), %r1
	bri %r1
	nop
	.type	__umodsi3,"function"
	.size	__umodsi3,.-__umodsi3
	.lcomm	.STACK,112,16
	.globl	mth_i_uimod
