gcc_compiled.:
.text
        .align 4
.globl _gcd
        nop
_gcd:
        adds -64,sp,sp
        st.l fp,56(sp)
        st.l r1,60(sp)
        adds 56,sp,fp
        st.l r4,0(sp)
        st.l r5,4(sp)
        st.l r6,8(sp)
        st.l r7,12(sp)
        st.l r8,16(sp)
        st.l r9,20(sp)
        mov r28,r4
        mov fp,r5
        addu -8,fp,r6
        st.l r16,0(r6)
        mov fp,r7
        addu -16,fp,r8
        st.l r17,0(r8)
.L2:
        mov fp,r16
        addu -16,fp,r16
        ld.l 0(r16),r16
        xor 0,r16,r0
        bc .L3
        mov fp,r16
        addu -24,fp,r9
        mov fp,r16
        addu -8,fp,r16
        mov fp,r17
        addu -16,fp,r17
        ld.l 0(r16),r16
        ld.l 0(r17),r17
        call ___umodsi3
        nop
        mov r16,r16
        st.l r16,0(r9)
        mov fp,r16
        addu -8,fp,r16
        mov fp,r17
        addu -16,fp,r17
        ld.l 0(r17),r18
        st.l r18,0(r16)
        mov fp,r16
        addu -16,fp,r16
        mov fp,r17
        addu -24,fp,r17
        ld.l 0(r17),r18
        st.l r18,0(r16)
        br .L2
        nop
.L3:
        mov fp,r16
        addu -8,fp,r16
        ld.l 0(r16),r16
        br .L1
        nop
.L1:
        ld.l -56(fp),r4
        ld.l -52(fp),r5
        ld.l -48(fp),r6
        ld.l -44(fp),r7
        ld.l -40(fp),r8
        ld.l -36(fp),r9
        ld.l 4(fp),r1
        ld.l 0(fp),fp
        bri r1
        addu 64,sp,sp
