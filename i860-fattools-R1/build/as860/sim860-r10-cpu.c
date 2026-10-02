/* I860FAT R1 bounded i860 interpreter.
   Runs the original Intel AS860 N1.3 i860 payload with the complete statically-linked
   SVR3 syscall surface needed by the assembler, binary-safe Win32 file services, and
   instruction semantics cross-checked against the Previous/Dimension i860 core.
   Guest exit returns a tagged status to the Win32 execution vehicle. */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed int s32;

extern u32 i860_text_size, i860_data_size, i860_bss_size;
extern u32 i860_entry, i860_text_guest, i860_data_guest, i860_low_size;
extern u32 i860_text_host, i860_data_host;
extern u32 i860_stack_guest, i860_stack_size, i860_stack_host;
extern u32 i860_run860_argv;
extern void host_puts_out(const char *s);
extern void host_puts_err(const char *s);
extern void host_puthex32(u32 v);
extern void host_force_verbose(void);
extern u32 host_write_fd(u32 fd, const void *p, u32 n);
extern u32 host_read_fd(u32 fd, void *p, u32 n);
extern u32 host_open_file(const char *path, u32 flags, u32 mode);
extern u32 host_creat_file(const char *path, u32 mode);
extern u32 host_close_fd(u32 fd);
extern u32 host_lseek_fd(u32 fd, u32 off, u32 whence);
extern u32 host_unlink_file(const char *path);
extern u32 host_filesize_fd(u32 fd);

static u32 r[32];
static u32 f[32];
static u32 cr[16];
static u32 cc;
static u32 lcc;
static u32 startup_argc;
static u32 pc;
static u32 icount;
static u32 fault_addr;
static u32 fault_kind;
static u32 write_traps;
static u32 write_bytes;
static u32 close_traps;
static u32 signal_traps;
static u32 utssys_traps;
static u32 brk_traps;
static u32 read_traps;
static u32 open_traps;
static u32 creat_traps;
static u32 unlink_traps;
static u32 time_traps;
static u32 stat_traps;
static u32 lseek_traps;
static u32 fstat_traps;
static u32 access_traps;
static u32 getpid_traps;
static u32 getuid_traps;
static u32 getgid_traps;
static u32 exit_traps;
static u32 guest_exit_status;
static u32 std_open_mask;
static u32 brk_floor;
static u32 brk_current;

#define INNER_REG_BASE 0x0001A5D0u
#define INNER_PC_ADDR  0x0001A760u
#define TARGET_ENTRY_PC 0xF04000C0u
#define TARGET_LOOP_PC  0xF04000CCu
#define TARGET_DELAY_PC 0xF04000D0u

#define TRACE_LIMIT 24u
#define STEP_LIMIT 20000000u
#define EXPECT_PC 0xF041B644u
#define EXPECT_WORD 0x47E0F800u
#define EXPECT_COUNT 9485u
#define EXPECT_WRITE_TRAPS 112u
#define EXPECT_CLOSE_TRAPS 3u
#define EXPECT_SIGNAL_TRAPS 1u
#define STARTUP_BASE 0x7fff0100u
#define STARTUP_LIMIT 0x7fff4000u

static int opmatch(u32 w, u32 match, u32 lose)
{
    return ((w & match) == match) && ((w & lose) == 0u);
}

static s32 sx16(u32 x)
{
    x &= 0xffffu;
    if (x & 0x8000u) x |= 0xffff0000u;
    return (s32)x;
}

static s32 sx26(u32 x)
{
    x &= 0x03ffffffu;
    if (x & 0x02000000u) x |= 0xfc000000u;
    return (s32)x;
}

static s32 split16(u32 w)
{
    u32 x;
    x = ((w >> 5) & 0xf800u) | (w & 0x07ffu);
    return sx16(x);
}

static void setr(u32 n, u32 v)
{
    if (n != 0u) r[n & 31u] = v;
}

static u8 *guest_ptr(u32 a, u32 n, int write_access)
{
    u32 off;
    if (n == 0u) return (u8 *)0;
    if (a >= i860_text_guest) {
        off = a - i860_text_guest;
        if (off <= i860_text_size && n <= i860_text_size - off) {
            if (write_access) {
                fault_addr = a; fault_kind = 2u; return (u8 *)0;
            }
            return (u8 *)(i860_text_host + off);
        }
    }
    if (a >= i860_data_guest) {
        off = a - i860_data_guest;
        if (off <= i860_low_size && n <= i860_low_size - off)
            return (u8 *)(i860_data_host + off);
    }
    if (a >= i860_stack_guest) {
        off = a - i860_stack_guest;
        if (off <= i860_stack_size && n <= i860_stack_size - off)
            return (u8 *)(i860_stack_host + off);
    }
    fault_addr = a; fault_kind = write_access ? 4u : 3u;
    return (u8 *)0;
}

static int read_mem(u32 a, u32 n, u32 *out)
{
    u8 *p;
    if ((n == 2u && (a & 1u)) || (n == 4u && (a & 3u))) {
        fault_addr = a; fault_kind = 5u; return 0;
    }
    p = guest_ptr(a,n,0);
    if (!p) return 0;
    if (n == 1u) {
        *out = (u32)p[0];
        if (*out & 0x80u) *out |= 0xffffff00u;
    } else if (n == 2u) {
        *out = (u32)p[0] | ((u32)p[1] << 8);
        if (*out & 0x8000u) *out |= 0xffff0000u;
    } else *out = (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
    return 1;
}

static int write_mem(u32 a, u32 n, u32 v)
{
    u8 *p;
    if ((n == 2u && (a & 1u)) || (n == 4u && (a & 3u))) {
        fault_addr = a; fault_kind = 5u; return 0;
    }
    p = guest_ptr(a,n,1);
    if (!p) return 0;
    p[0] = (u8)v;
    if (n >= 2u) p[1] = (u8)(v >> 8);
    if (n >= 4u) { p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24); }
    return 1;
}

/* i860 floating registers are 32 bits each. A double uses an even register
   and the following register. This target is little-endian, so the first
   register supplies the low-address 32-bit word. */
static int write_fpair64(u32 a, u32 freg)
{
    u8 *p;
    u32 lo, hi;
    if ((a & 7u) != 0u) {
        fault_addr = a; fault_kind = 5u; return 0;
    }
    if ((freg & 1u) != 0u || freg >= 31u) return 0;
    p = guest_ptr(a,8u,1);
    if (!p) return 0;
    lo=f[freg]; hi=f[freg+1u];
    p[0]=(u8)lo; p[1]=(u8)(lo>>8); p[2]=(u8)(lo>>16); p[3]=(u8)(lo>>24);
    p[4]=(u8)hi; p[5]=(u8)(hi>>8); p[6]=(u8)(hi>>16); p[7]=(u8)(hi>>24);
    return 1;
}

static int write_fwords(u32 a, u32 freg, u32 words)
{
    u32 i,align;
    align=words*4u;
    if (words==0u || words>4u || (a & (align-1u))!=0u ||
        (freg & (words-1u))!=0u || freg+words>32u) {
        fault_addr=a; fault_kind=5u; return 0;
    }
    for (i=0u;i<words;i++) if (!write_mem(a+i*4u,4u,f[freg+i])) return 0;
    return 1;
}

static int read_fwords(u32 a, u32 freg, u32 words)
{
    u32 i,align,v;
    align=words*4u;
    if (words==0u || words>4u || (a & (align-1u))!=0u ||
        (freg & (words-1u))!=0u || freg+words>32u) {
        fault_addr=a; fault_kind=5u; return 0;
    }
    for (i=0u;i<words;i++) {
        if (!read_mem(a+i*4u,4u,&v)) return 0;
        f[freg+i]=v;
    }
    return 1;
}

typedef union I860_DBL_BITS { double d; u32 w[2]; } I860_DBL_BITS;
static double get_f64(u32 freg)
{
    I860_DBL_BITS x; x.w[0]=f[freg]; x.w[1]=f[freg+1u]; return x.d;
}
static void set_f64(u32 freg,double v)
{
    I860_DBL_BITS x; x.d=v; f[freg]=x.w[0]; f[freg+1u]=x.w[1];
}

static int guest_store_utsname(u32 a)
{
    u8 *p;
    static const char *fields[5] = {"UNIX", "run860", "3.2", "N1.3", "i860"};
    u32 i,j;
    p=guest_ptr(a,45u,1);
    if (!p) return 0;
    for (i=0u;i<45u;i++) p[i]=0u;
    for (i=0u;i<5u;i++) {
        for (j=0u;j<8u && fields[i][j];j++) p[i*9u+j]=(u8)fields[i][j];
    }
    return 1;
}

static const char *guest_cstr(u32 a)
{
    u8 *p;
    u32 i;
    p=guest_ptr(a,1u,0);
    if (!p) return (const char *)0;
    for (i=0u;i<1024u;i++) {
        p=guest_ptr(a+i,1u,0);
        if (!p) return (const char *)0;
        if (*p==0u) return (const char *)guest_ptr(a,i+1u,0);
    }
    return (const char *)0;
}

static char host_path_buf[1024];
static int path_prefix(const char *s,const char *p)
{
    u32 i; for (i=0u;p[i];i++) if (s[i]!=p[i]) return 0; return 1;
}
static const char *guest_host_path(u32 a,int *is_dir)
{
    const char *s,*q; u32 i,j;
    s=guest_cstr(a); if (!s) return (const char *)0;
    *is_dir=0; q=s;
    if (path_prefix(s,"/usr/tmp/")) { q=s+9; if (!*q) *is_dir=1; }
    else if (path_prefix(s,"/tmp/")) { q=s+5; if (!*q) *is_dir=1; }
    else if (path_prefix(s,"\\tmp\\")) { q=s+5; if (!*q) *is_dir=1; }
    else if ((s[0]=='.' && s[1]==0) || (s[0]=='/' && s[1]==0)) { q=s+1; *is_dir=1; }
    else if ((path_prefix(s,"/usr/tmp") && s[8]==0) || (path_prefix(s,"/tmp") && s[4]==0) ||
             (path_prefix(s,"\\tmp") && s[4]==0)) { q=s+(s[1]=='u'?8:4); *is_dir=1; }
    if (*is_dir) { host_path_buf[0]='.'; host_path_buf[1]=0; return host_path_buf; }
    for (i=0u,j=0u;q[i] && j<1023u;i++) {
        char c; c=q[i]; if (c=='/') c='\\'; host_path_buf[j++]=c;
    }
    host_path_buf[j]=0;
    if (j==0u) { host_path_buf[0]='.'; host_path_buf[1]=0; *is_dir=1; }
    return host_path_buf;
}

static void put16le(u8 *p,u32 v)
{
    p[0]=(u8)v; p[1]=(u8)(v>>8);
}

static void put32le(u8 *p,u32 v)
{
    p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24);
}

/* Old System V struct stat used by this N1.3 binary:
   short dev; ushort ino,mode; short nlink; ushort uid,gid; short rdev;
   2-byte ABI alignment pad; long size,atime,mtime,ctime. Total 32 bytes. */
static int guest_store_stat(u32 a,u32 size,u32 mode)
{
    u8 *p; u32 i;
    p=guest_ptr(a,32u,1);
    if (!p) return 0;
    for (i=0u;i<32u;i++) p[i]=0u;
    put16le(p+0,0u);           /* st_dev */
    put16le(p+2,1u);           /* st_ino */
    put16le(p+4,mode);         /* st_mode */
    put16le(p+6,1u);           /* st_nlink */
    put16le(p+8,0u);           /* st_uid */
    put16le(p+10,0u);          /* st_gid */
    put16le(p+12,0u);          /* st_rdev */
    put32le(p+16,size);        /* st_size */
    put32le(p+20,631152000u);  /* 1990-01-01 UTC, deterministic */
    put32le(p+24,631152000u);
    put32le(p+28,631152000u);
    return 1;
}

static void trace_insn(u32 at, u32 w)
{
    if (icount > TRACE_LIMIT) return;
    host_puts_out("I860FAT R1: TRACE #0x"); host_puthex32(icount);
    host_puts_out(" pc=0x"); host_puthex32(at);
    host_puts_out(" insn=0x"); host_puthex32(w);
    host_puts_out("\r\n");
    if (icount == TRACE_LIMIT)
        host_puts_out("I860FAT R1: trace suppressed after first 24 instructions\r\n");
}

/* Build the i860-side process startup contract that run860 would have supplied.
   The outer historical wrapper passes run860 an argv vector of:
       run860, fat-binary-path, original-user-args...
   The i860 program therefore receives argv beginning at element 1.  r16/r17/r18
   carry argc/argv/envp; a compact pointer/string area is placed safely near the
   bottom of the synthetic guest stack, away from the live stack top. */
static u32 host_strlen_bounded(const char *s, u32 lim)
{
    u32 n;
    if (!s) return 0xffffffffu;
    for (n=0u;n<lim;n++) if (s[n]==0) return n;
    return 0xffffffffu;
}

static int setup_startup(void)
{
    u32 *hav;
    u32 argc, i, cur, argv_addr, envp_addr, n;
    const char *hs;
    u8 *p;
    static const char path_s[] = "PATH=.";
    hav=(u32 *)i860_run860_argv;
    if (!hav) return 0;
    argc=0u;
    while (argc<62u && hav[argc+1u]!=0u) argc++;
    if (argc==0u) return 0;

    cur=STARTUP_BASE;
    /* Reserve argv pointers + NULL and envp pointer + NULL first. */
    argv_addr=cur;
    cur += (argc+1u)*4u;
    envp_addr=cur;
    cur += 8u;
    cur=(cur+3u)&~3u;
    if (cur>=STARTUP_LIMIT) return 0;

    for (i=0u;i<argc;i++) {
        hs=(const char *)hav[i+1u];
        n=host_strlen_bounded(hs,1023u);
        if (n==0xffffffffu || cur+n+1u>STARTUP_LIMIT) return 0;
        p=guest_ptr(cur,n+1u,1);
        if (!p) return 0;
        {
            u32 j;
            for (j=0u;j<=n;j++) p[j]=(u8)hs[j];
        }
        if (!write_mem(argv_addr+i*4u,4u,cur)) return 0;
        cur += n+1u;
    }
    if (!write_mem(argv_addr+argc*4u,4u,0u)) return 0;

    n=(u32)(sizeof(path_s));
    p=guest_ptr(cur,n,1);
    if (!p) return 0;
    for (i=0u;i<n;i++) p[i]=(u8)path_s[i];
    if (!write_mem(envp_addr,4u,cur)) return 0;
    if (!write_mem(envp_addr+4u,4u,0u)) return 0;

    r[16]=argc;
    r[17]=argv_addr;
    r[18]=envp_addr;
    return 1;
}

/* Execute only a non-control instruction. Return 1 if supported, 0 otherwise,
   and -1 for a memory fault. */
static int exec_noncontrol(u32 at, u32 w)
{
    u32 s1, s2, d, a, b, v, n, off;
    s1 = (w >> 11) & 31u;
    s2 = (w >> 21) & 31u;
    d = (w >> 16) & 31u;

    if (opmatch(w,0x30000000u,0xcc000000u)) { setr(d,cr[s2 & 15u]); pc = at + 4u; return 1; }
    if (opmatch(w,0x38000000u,0xc4000000u)) { cr[s2 & 15u] = r[s1]; pc = at + 4u; return 1; }

    /* ixfr: transfer integer register bits to a floating register. */
    if (opmatch(w,0x08000000u,0xf4000000u)) { f[d]=r[s1]; pc=at+4u; return 1; }

    /* fmlow.dd is used by the N1.3 runtime for 32-bit integer multiply:
       ixfr operands into FP regs, fmlow.dd, then fxfr the low product back. */
    if (opmatch(w,0x480001a1u,0xb400065eu)) {
        f[d]=f[s1]*f[s2]; if (d<31u) f[d+1u]=0u; pc=at+4u; return 1;
    }
    /* fxfr: transfer low 32-bit floating-register bits to an integer reg. */
    if (opmatch(w,0x48000040u,0xb40007bfu)) { setr(d,f[s1]); pc=at+4u; return 1; }
    /* fiadd.ss: 32-bit integer add in the floating register file.  This
       also implements the fmov.ss pseudo-op when fsrc2 is f0. */
    if (opmatch(w,0x48000049u,0xb40007b6u)) { f[d]=f[s1]+f[s2]; pc=at+4u; return 1; }
    /* fiadd.dd: 64-bit long-integer add across an even/odd FP-register pair.
       fmov.dd is the architectural pseudo-op fiadd.dd fsrc1,f0,fdest. */
    if (opmatch(w,0x480001c9u,0xb4000436u)) {
        u32 alo,ahi,blo,bhi,lo,hi,carry;
        if ((s1&1u)||(s2&1u)||(d&1u)||s1>=31u||s2>=31u||d>=31u) return 0;
        alo=f[s1]; ahi=f[s1+1u]; blo=f[s2]; bhi=f[s2+1u];
        lo=alo+blo; carry=(lo<alo)?1u:0u; hi=ahi+bhi+carry;
        f[d]=lo; f[d+1u]=hi; pc=at+4u; return 1;
    }
    /* Scalar double addition/subtraction used by Intel's numeric runtimes. */
    if (opmatch(w,0x480001b0u,0xb400044fu)) {
        if ((s1&1u)||(s2&1u)||(d&1u)||s1>=31u||s2>=31u||d>=31u) return 0;
        set_f64(d,get_f64(s1)+get_f64(s2)); pc=at+4u; return 1;
    }
    /* Scalar double subtraction used by the assembler's numeric runtime. */
    if (opmatch(w,0x480001b1u,0xb400044eu)) {
        if ((s1&1u)||(s2&1u)||(d&1u)||s1>=31u||s2>=31u||d>=31u) return 0;
        set_f64(d,get_f64(s1)-get_f64(s2)); pc=at+4u; return 1;
    }
    if (opmatch(w,0x480001a2u,0xb400065du)) {
        if ((s2&1u)||(d&1u)||s2>=31u||d>=31u) return 0;
        set_f64(d,1.0/get_f64(s2)); pc=at+4u; return 1;
    }
    if (opmatch(w,0x480001a0u,0xb400065fu)) {
        if ((s1&1u)||(s2&1u)||(d&1u)||s1>=31u||s2>=31u||d>=31u) return 0;
        set_f64(d,get_f64(s1)*get_f64(s2)); pc=at+4u; return 1;
    }
    if (opmatch(w,0x480001bau,0xb4000445u)) {
        s32 iv;
        if ((s1&1u)||(d&1u)||s1>=31u||d>=31u) return 0;
        iv=(s32)get_f64(s1); f[d]=(u32)iv; f[d+1u]=0u; pc=at+4u; return 1;
    }

    /* Floating loads: the immediate is aligned to operand width.  With
       autoincrement, src2 receives the effective address after the load. */
    if (opmatch(w,0x24000002u,0xd8000001u)) { off=(u32)sx16(w)&~3u; if (!read_fwords(r[s2]+off,d,1u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x20000002u,0xdc000001u)) { if (!read_fwords(r[s2]+r[s1],d,1u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x24000003u,0xd8000000u)) { off=(u32)sx16(w)&~3u; a=r[s2]+off; if (!read_fwords(a,d,1u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x20000003u,0xdc000000u)) { a=r[s2]+r[s1]; if (!read_fwords(a,d,1u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x24000000u,0xd8000007u)) { off=(u32)sx16(w)&~7u; if (!read_fwords(r[s2]+off,d,2u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x20000000u,0xdc000007u)) { if (!read_fwords(r[s2]+r[s1],d,2u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x24000001u,0xd8000006u)) { off=(u32)sx16(w)&~7u; a=r[s2]+off; if (!read_fwords(a,d,2u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x20000001u,0xdc000006u)) { a=r[s2]+r[s1]; if (!read_fwords(a,d,2u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x24000004u,0xd8000003u)) { off=(u32)sx16(w)&~15u; if (!read_fwords(r[s2]+off,d,4u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x20000004u,0xdc000003u)) { if (!read_fwords(r[s2]+r[s1],d,4u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x24000005u,0xd8000002u)) { off=(u32)sx16(w)&~15u; a=r[s2]+off; if (!read_fwords(a,d,4u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x20000005u,0xdc000002u)) { a=r[s2]+r[s1]; if (!read_fwords(a,d,4u)) return -1; setr(s2,a); pc=at+4u; return 1; }

    /* AS860 uses quad FP stores to spill register-save areas.  In i860
       autoincrement addressing src2 is replaced by the effective address. */
    if (opmatch(w,0x2c000005u,0xd0000002u)) {
        off=(u32)sx16(w) & ~15u; a=r[s2]+off;
        if (!write_fwords(a,d,4u)) return -1;
        setr(s2,a); pc=at+4u; return 1;
    }
    if (opmatch(w,0x28000005u,0xd4000002u)) {
        a=r[s2]+r[s1];
        if (!write_fwords(a,d,4u)) return -1;
        setr(s2,a); pc=at+4u; return 1;
    }
    if (opmatch(w,0x2c000004u,0xd0000003u)) {
        off=(u32)sx16(w) & ~15u;
        if (!write_fwords(r[s2]+off,d,4u)) return -1;
        pc=at+4u; return 1;
    }
    if (opmatch(w,0x28000004u,0xd4000003u)) {
        if (!write_fwords(r[s2]+r[s1],d,4u)) return -1;
        pc=at+4u; return 1;
    }

    /* Single/double floating stores, including autoincrement forms. */
    if (opmatch(w,0x2c000002u,0xd0000001u)) { off=(u32)sx16(w)&~3u; if (!write_fwords(r[s2]+off,d,1u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x28000002u,0xd4000001u)) { if (!write_fwords(r[s2]+r[s1],d,1u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x2c000003u,0xd0000000u)) { off=(u32)sx16(w)&~3u; a=r[s2]+off; if (!write_fwords(a,d,1u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x28000003u,0xd4000000u)) { a=r[s2]+r[s1]; if (!write_fwords(a,d,1u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x2c000001u,0xd0000006u)) { off=(u32)sx16(w)&~7u; a=r[s2]+off; if (!write_fwords(a,d,2u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x28000001u,0xd4000006u)) { a=r[s2]+r[s1]; if (!write_fwords(a,d,2u)) return -1; setr(s2,a); pc=at+4u; return 1; }

    /* R8 preserved floating-point operation: normal fst.d. GNU's opcode table
       defines immediate fst.d as 0x2c000000/0xd0000007 with an 8-byte-aligned
       signed immediate, and register-indexed fst.d as 0x28000000/0xd4000007. */
    if (opmatch(w,0x2c000000u,0xd0000007u)) {
        off=(u32)sx16(w) & ~7u;
        if (!write_fpair64(r[s2]+off,d)) return -1;
        pc=at+4u; return 1;
    }
    if (opmatch(w,0x28000000u,0xd4000007u)) {
        if (!write_fpair64(r[s2]+r[s1],d)) return -1;
        pc=at+4u; return 1;
    }

    if (opmatch(w,0x0c000000u,0xf0000000u)) n=1u;
    else if (opmatch(w,0x1c000000u,0xe0000001u)) n=2u;
    else if (opmatch(w,0x1c000001u,0xe0000000u)) n=4u;
    else n=0u;
    if (n) {
        off = (u32)split16(w) & ~(n-1u);
        if (!write_mem(r[s2] + off,n,r[s1])) return -1;
        pc = at + 4u; return 1;
    }

    if (opmatch(w,0x00000000u,0xfc000000u)) { n=1u; off=r[s1]; }
    else if (opmatch(w,0x04000000u,0xf8000000u)) { n=1u; off=(u32)sx16(w); }
    else if (opmatch(w,0x10000000u,0xec000001u)) { n=2u; off=r[s1]; }
    else if (opmatch(w,0x14000000u,0xe8000001u)) { n=2u; off=(u32)sx16(w) & ~1u; }
    else if (opmatch(w,0x10000001u,0xec000000u)) { n=4u; off=r[s1]; }
    else if (opmatch(w,0x14000001u,0xe8000000u)) { n=4u; off=(u32)sx16(w) & ~3u; }
    else n=0u;
    if (n) {
        if (!read_mem(r[s2] + off,n,&v)) return -1;
        setr(d,v); pc=at+4u; return 1;
    }

#define ARITH(MATCH,LOSE,IMM,OP) \
    if (opmatch(w,(MATCH),(LOSE))) { \
        a = (IMM) ? (u32)sx16(w) : r[s1]; b = r[s2]; \
        if ((OP)==0u) { v=a+b; cc=(v<a); } \
        else if ((OP)==1u) { v=a+b; cc=((s32)b < (s32)(0u-a)); } \
        else if ((OP)==2u) { v=a-b; cc=(b<=a); } \
        else { v=a-b; cc=((s32)b > (s32)a); } \
        setr(d,v); pc=at+4u; return 1; \
    }
    ARITH(0x80000000u,0x7c000000u,0,0u)
    ARITH(0x84000000u,0x78000000u,1,0u)
    ARITH(0x90000000u,0x6c000000u,0,1u)
    ARITH(0x94000000u,0x68000000u,1,1u)
    ARITH(0x88000000u,0x74000000u,0,2u)
    ARITH(0x8c000000u,0x70000000u,1,2u)
    ARITH(0x98000000u,0x64000000u,0,3u)
    ARITH(0x9c000000u,0x60000000u,1,3u)
#undef ARITH

#define SHIFT(MATCH,LOSE,IMM,OP) \
    if (opmatch(w,(MATCH),(LOSE))) { \
        a=((IMM) ? (w & 0xffffu) : r[s1]) & 31u; b=r[s2]; \
        if ((OP)==0u) v=b<<a; else if ((OP)==1u) v=b>>a; else v=(u32)(((s32)b)>>a); \
        setr(d,v); pc=at+4u; return 1; \
    }
    SHIFT(0xa0000000u,0x5c000000u,0,0u)
    SHIFT(0xa4000000u,0x58000000u,1,0u)
    SHIFT(0xa8000000u,0x54000000u,0,1u)
    SHIFT(0xac000000u,0x50000000u,1,1u)
    SHIFT(0xb8000000u,0x44000000u,0,2u)
    SHIFT(0xbc000000u,0x40000000u,1,2u)
#undef SHIFT

#define LOGIC(MATCH,LOSE,IMM,HIGH,OP) \
    if (opmatch(w,(MATCH),(LOSE))) { \
        a=(IMM) ? (w & 0xffffu) : r[s1]; if (HIGH) a <<= 16; b=r[s2]; \
        if ((OP)==0u) v=a&b; else if ((OP)==1u) v=(~a)&b; else if ((OP)==2u) v=a|b; else v=a^b; \
        cc=(v==0u); setr(d,v); pc=at+4u; return 1; \
    }
    LOGIC(0xc0000000u,0x3c000000u,0,0,0u)
    LOGIC(0xc4000000u,0x38000000u,1,0,0u)
    LOGIC(0xcc000000u,0x30000000u,1,1,0u)
    LOGIC(0xd0000000u,0x2c000000u,0,0,1u)
    LOGIC(0xd4000000u,0x28000000u,1,0,1u)
    LOGIC(0xdc000000u,0x20000000u,1,1,1u)
    LOGIC(0xe0000000u,0x1c000000u,0,0,2u)
    LOGIC(0xe4000000u,0x18000000u,1,0,2u)
    LOGIC(0xec000000u,0x10000000u,1,1,2u)
    LOGIC(0xf0000000u,0x0c000000u,0,0,3u)
    LOGIC(0xf4000000u,0x08000000u,1,0,3u)
    LOGIC(0xfc000000u,0x00000000u,1,1,3u)
#undef LOGIC

    if (opmatch(w,0x58000000u,0xa4000000u) || opmatch(w,0x5c000000u,0xa0000000u) ||
        opmatch(w,0x50000000u,0xac000000u) || opmatch(w,0x54000000u,0xa8000000u)) {
        int neq, imm, take;
        neq = opmatch(w,0x50000000u,0xac000000u) || opmatch(w,0x54000000u,0xa8000000u);
        imm = opmatch(w,0x5c000000u,0xa0000000u) || opmatch(w,0x54000000u,0xa8000000u);
        a = imm ? s1 : r[s1]; b=r[s2]; take=(a==b); if (neq) take=!take;
        pc = take ? at + 4u + (u32)(split16(w)*4) : at + 4u; return 1;
    }

    if (opmatch(w,0x70000000u,0x8c000000u)) { pc=cc ? at+4u+(u32)(sx26(w)*4) : at+4u; return 1; }
    if (opmatch(w,0x78000000u,0x84000000u)) { pc=!cc ? at+4u+(u32)(sx26(w)*4) : at+4u; return 1; }

    return 0;
}

static int fetch_trace(u32 at, u32 *w)
{
    if (!read_mem(at,4u,w)) return 0;
    ++icount; trace_insn(at,*w); return 1;
}

static int exec_delay(u32 at)
{
    u32 w; int rc;
    if (!fetch_trace(at,&w)) return -1;
    rc=exec_noncontrol(at,w);
    if (rc <= 0) { pc=at; return rc ? rc : 0; }
    return 1;
}

/* Return 2 clean guest exit, 1 supported/progressed, 0 unsupported, -1 memory fault. */
static int step_one(void)
{
    u32 at,w,s1,target; int rc,cond;
    at=pc;
    if (!fetch_trace(at,&w)) return -1;
    s1=(w>>11)&31u;

    if (opmatch(w,0x68000000u,0x94000000u) || opmatch(w,0x6c000000u,0x90000000u)) {
        int is_call;
        target=at+4u+(u32)(sx26(w)*4);
        is_call=opmatch(w,0x6c000000u,0x90000000u);
        rc=exec_delay(at+4u); if (rc<=0) return rc;
        /* Relative call writes r1 after the delay slot; the delay-slot
           instruction therefore sees the old r1. */
        if (is_call) setr(1u,at+8u);
        pc=target; return 1;
    }
    if (opmatch(w,0x40000000u,0xbc000000u)) {
        target=r[s1]; rc=exec_delay(at+4u); if (rc<=0) return rc; pc=target; return 1;
    }
    if (opmatch(w,0x4c000002u,0xb000001du)) {
        target=r[s1]; setr(1u,at+8u); rc=exec_delay(at+4u); if (rc<=0) return rc; pc=target; return 1;
    }
    if (opmatch(w,0x74000000u,0x88000000u) || opmatch(w,0x7c000000u,0x80000000u)) {
        cond=opmatch(w,0x74000000u,0x88000000u) ? (cc!=0u) : (cc==0u);
        target=at+4u+(u32)(sx26(w)*4);
        /* bc.t/bnc.t execute the delay-slot instruction only when the
           branch is taken.  A not-taken branch skips directly to at+8. */
        if (cond) { rc=exec_delay(at+4u); if (rc<=0) return rc; pc=target; }
        else pc=at+8u;
        return 1;
    }
    /* bla: branch on old LCC, add, then install the comparison-derived
       new LCC after the delay slot. */
    if (opmatch(w,0xb4000000u,0x48000000u)) {
        u32 old_lcc,sum,s2,src1v,orig2,new_lcc;
        s2=(w>>21)&31u; src1v=r[(w>>11)&31u]; orig2=r[s2]; old_lcc=lcc;
        /* i860 definition: new LCC = signed(old src2) >= -signed(src1).
           Compute the negation in unsigned space to avoid host signed-overflow UB. */
        new_lcc=((s32)orig2 >= (s32)(0u-src1v)) ? 1u : 0u;
        sum=orig2+src1v;
        setr(s2,sum);
        target=at+4u+(u32)(split16(w)*4);
        rc=exec_delay(at+4u); if (rc<=0) return rc;
        lcc=new_lcc;
        pc=old_lcc ? target : at+8u; return 1;
    }
    /* i860 System V host traps. R8 preserves live-proven write(4) and close(6)
       and adds only exit(1). Standard descriptors remain logical guest state:
       guest close does not destroy Win32 console HANDLEs needed for diagnostics. */
    if (opmatch(w,0x44000000u,0xb8000000u)) {
        if (r[31]==1u) {
            ++exit_traps;
            guest_exit_status=r[16] & 0xffu;
            pc=at+4u;
            return 2;
        }
        if (r[31]==3u) {
            u8 *p; u32 rv,fd;
            fd=r[16]; p=guest_ptr(r[17],r[18],1);
            ++read_traps;
            if (!p && r[18]!=0u) return -1;
            rv=host_read_fd(fd,p,r[18]);
            if (rv==0xffffffffu) { r[16]=5u; cc=1u; }
            else { r[16]=rv; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==4u) {
            u8 *p; u32 rv,fd;
            fd=r[16];
            if (fd<=2u && (std_open_mask & (1u<<fd))==0u) { r[16]=9u; cc=1u; pc=at+4u; return 1; }
            p=guest_ptr(r[17],r[18],0);
            if (!p && r[18]!=0u) return -1;
            rv=host_write_fd(fd,p,r[18]);
            ++write_traps;
            if (rv==0xffffffffu) { r[16]=5u; cc=1u; }
            else { r[16]=rv; write_bytes+=rv; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==5u) {
            const char *path; u32 rv; int is_dir;
            ++open_traps; path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            rv=host_open_file(path,r[17],r[18]);
            if (rv==0xffffffffu) { r[16]=2u; cc=1u; }
            else { r[16]=rv; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==6u) {
            u32 fd; fd=r[16]; ++close_traps;
            if (fd<=2u && (std_open_mask & (1u<<fd))!=0u) {
                std_open_mask &= ~(1u<<fd); r[16]=0u; cc=0u; pc=at+4u; return 1;
            }
            if (fd>2u && host_close_fd(fd)==0u) { r[16]=0u; cc=0u; pc=at+4u; return 1; }
            r[16]=9u; cc=1u; pc=at+4u; return 1;
        }
        if (r[31]==8u) {
            const char *path; u32 rv; int is_dir;
            ++creat_traps; path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            rv=host_creat_file(path,r[17]);
            if (rv==0xffffffffu) { r[16]=5u; cc=1u; }
            else { r[16]=rv; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==10u) {
            const char *path; u32 rv; int is_dir;
            ++unlink_traps; path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            rv=host_unlink_file(path);
            if (rv==0xffffffffu) { r[16]=2u; cc=1u; }
            else { r[16]=0u; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==13u) {
            u32 now;
            ++time_traps; now=631152000u;
            if (r[16]!=0u && !write_mem(r[16],4u,now)) return -1;
            r[16]=now; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==15u) {
            const char *path; u32 fd; int is_dir;
            path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            if (!is_dir) {
                fd=host_open_file(path,0u,0u);
                if (fd==0xffffffffu) { r[16]=2u; cc=1u; pc=at+4u; return 1; }
                (void)host_close_fd(fd);
            }
            r[16]=0u; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==17u) {
            u32 req;
            req=r[16]; ++brk_traps;
            if (req>=brk_floor && req<i860_data_guest+i860_low_size) {
                brk_current=req; r[16]=0u; cc=0u; pc=at+4u; return 1;
            }
            r[16]=12u; cc=1u; pc=at+4u; return 1;
        }
        if (r[31]==18u) {
            const char *path; u32 fd,sz; int is_dir;
            ++stat_traps; path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            if (is_dir) {
                if (!guest_store_stat(r[17],0u,0x41ffu)) { r[16]=14u; cc=1u; }
                else { r[16]=0u; cc=0u; }
                pc=at+4u; return 1;
            }
            fd=host_open_file(path,0u,0u);
            if (fd==0xffffffffu) { r[16]=2u; cc=1u; pc=at+4u; return 1; }
            sz=host_filesize_fd(fd); (void)host_close_fd(fd);
            if (sz==0xffffffffu || !guest_store_stat(r[17],sz,0x81b6u)) { r[16]=5u; cc=1u; }
            else { r[16]=0u; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==19u) {
            u32 rv;
            ++lseek_traps; rv=host_lseek_fd(r[16],r[17],r[18]);
            if (rv==0xffffffffu) { r[16]=22u; cc=1u; }
            else { r[16]=rv; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==28u) {
            u32 sz,mode;
            ++fstat_traps;
            if (r[16]<=2u) { sz=0u; mode=0x21b6u; }
            else { sz=host_filesize_fd(r[16]); mode=0x81b6u; }
            if (sz==0xffffffffu || !guest_store_stat(r[17],sz,mode)) { r[16]=9u; cc=1u; }
            else { r[16]=0u; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==20u) {
            ++getpid_traps; r[16]=1u; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==24u) {
            ++getuid_traps; r[16]=0u; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==33u) {
            const char *path; u32 fd; int is_dir;
            ++access_traps; path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            if (is_dir) { r[16]=0u; cc=0u; pc=at+4u; return 1; }
            fd=host_open_file(path,0u,0u);
            if (fd==0xffffffffu) { r[16]=2u; cc=1u; }
            else { (void)host_close_fd(fd); r[16]=0u; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==47u) {
            ++getgid_traps; r[16]=0u; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==48u) {
            /* Match the already-proven outer SVR3 personality policy: accept
               signal disposition registration, but provide no async delivery. */
            ++signal_traps; r[16]=0u; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==57u) {
            /* SCO/SVR3 utssys(buf,0,0): the uname form.  Return a deterministic
               classic five-by-nine-byte struct utsname, not modern host data. */
            ++utssys_traps;
            if (r[17]==0u && r[18]==0u && guest_store_utsname(r[16])) {
                r[16]=0u; cc=0u; pc=at+4u; return 1;
            }
            r[16]=14u; cc=1u; pc=at+4u; return 1;
        }
        return 0;
    }
    return exec_noncontrol(at,w);
}

static void generic_print_counts(void)
{
    host_puts_out("I860FAT R1: traps write=0x"); host_puthex32(write_traps);
    host_puts_out(" read=0x"); host_puthex32(read_traps);
    host_puts_out(" open=0x"); host_puthex32(open_traps);
    host_puts_out(" close=0x"); host_puthex32(close_traps);
    host_puts_out(" brk=0x"); host_puthex32(brk_traps);
    host_puts_out(" lseek=0x"); host_puthex32(lseek_traps);
    host_puts_out(" signal=0x"); host_puthex32(signal_traps);
    host_puts_out("\r\n");
}

int i860_run(void)
{
    u32 i,w; int rc;
    for (i=0u;i<32u;i++) { r[i]=0u; f[i]=0u; }
    for (i=0u;i<16u;i++) cr[i]=0u;
    cc=0u; lcc=0u; startup_argc=0u; icount=0u; fault_addr=0u; fault_kind=0u;
    write_traps=0u; write_bytes=0u; close_traps=0u; signal_traps=0u; utssys_traps=0u; brk_traps=0u;
    read_traps=0u; open_traps=0u; creat_traps=0u; unlink_traps=0u; time_traps=0u; stat_traps=0u; lseek_traps=0u; fstat_traps=0u;
    access_traps=0u; getpid_traps=0u; getuid_traps=0u; getgid_traps=0u; exit_traps=0u; guest_exit_status=0u; std_open_mask=7u;
    brk_floor=i860_data_guest+i860_data_size+i860_bss_size; brk_current=brk_floor;
    r[2]=i860_stack_guest+i860_stack_size-16u;
    if (!setup_startup()) {
        host_force_verbose();
        host_puts_err("I860FAT R1: unable to construct i860 argc/argv/envp startup state\r\n");
        return 1;
    }
    startup_argc=r[16];
    pc=i860_entry;
    host_puts_out("I860FAT R1: i860 entry=0x"); host_puthex32(pc);
    host_puts_out(" synthetic-sp=0x"); host_puthex32(r[2]);
    host_puts_out(" argc=0x"); host_puthex32(r[16]);
    host_puts_out(" argv=0x"); host_puthex32(r[17]);
    host_puts_out(" envp=0x"); host_puthex32(r[18]); host_puts_out("\r\n");

    for (i=0u;i<STEP_LIMIT;i++) {
        rc=step_one();
        if (rc<0) {
            host_force_verbose();
            host_puts_err("I860FAT R1: i860 MEMORY FAULT kind=0x"); host_puthex32(fault_kind);
            host_puts_err(" address=0x"); host_puthex32(fault_addr); host_puts_err(" pc=0x"); host_puthex32(pc); host_puts_err("\r\n");
            generic_print_counts();
            return 1;
        }
        if (rc==2) {
            host_puts_out("I860FAT R1: guest exit status=0x"); host_puthex32(guest_exit_status);
            host_puts_out(" count=0x"); host_puthex32(icount); host_puts_out("\r\n");
            generic_print_counts();
            return 0x100u + guest_exit_status;
        }
        if (rc==0) {
            if (!read_mem(pc,4u,&w)) w=0u;
            host_force_verbose();
            host_puts_out("I860FAT R1: unsupported i860 instruction/service pc=0x"); host_puthex32(pc);
            host_puts_out(" insn=0x"); host_puthex32(w); host_puts_out(" count=0x"); host_puthex32(icount); host_puts_out("\r\n");
            if (opmatch(w,0x44000000u,0xb8000000u)) {
                host_puts_out("I860FAT R1: UNKNOWN TRAP r31=0x"); host_puthex32(r[31]);
                host_puts_out(" r16=0x"); host_puthex32(r[16]); host_puts_out(" r17=0x"); host_puthex32(r[17]);
                host_puts_out(" r18=0x"); host_puthex32(r[18]); host_puts_out(" r19=0x"); host_puthex32(r[19]); host_puts_out("\r\n");
            }
            generic_print_counts();
            return 1;
        }
    }
    host_force_verbose();
    host_puts_err("I860FAT R1: bounded i860 step limit reached without guest exit\r\n");
    generic_print_counts();
    return 1;
}
