/* Real x87 precision-exception regression; host Linux C test, NOT a PE runner.
   The control words and reciprocal operand match the audited SIM860 path.
   Original SIGFPE-tail execution is separately tested in test_precision_bridge.py. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    volatile double one=1.0, operand=462.0, result;
    unsigned short original=0x0240, working=argc>1?0x0260:0x0240;
    unsigned short status, restored;
    uint64_t bits;
    (void)argv;
    __asm__ volatile("fninit; fldcw %2; fldl %3; fdivl %4; fstpl %0; fnstsw %1"
        : "=m"(result), "=m"(status)
        : "m"(working), "m"(one), "m"(operand) : "memory");
    /* Model precision-only cleanup, retaining actual native arithmetic. */
    __asm__ volatile("fnclex; fldcw %1; fnstcw %0"
        : "=m"(restored) : "m"(original) : "memory");
    __asm__ volatile("fninit");
    memcpy(&bits,(const void *)&result,sizeof(bits));
    printf("%016llx %04x %04x\n",(unsigned long long)bits,status,restored);
    return 0;
}
