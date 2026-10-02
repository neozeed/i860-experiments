/****************************************************************************
 **                                                                        **
 **                (C) Copyright 1991 Intel Corporation                    **
 **                        All rights reserved                             **
 **                                                                        **
 **              INTEL CORPORATION PROPRIETARY INFORMATION                 **
 **                                                                        **
 **  This software is supplied under the terms of a license agreement or   **
 **  nondisclosure agreement with Intel Corporation and may not be copied  **  
 **  or disclosed except in accordance with the terms of that agreement.   **
 **                                                                        **
 **                                                                        **
 ****************************************************************************/

/***************************************************************************
 *    
 *    Title:
 *	trace.c 8.12 91/04/18 05:58:56
 *    
 *    Description:
 *        Trace table specifying which procedures wil be event traced.
 *    
 **************************************************************************/


typedef	void (*fcnp)();

#define NO_PARAM	-1
#define USER_FCN	0
#define COMM_FCN	1
#define IO_FCN		2
#define SYS_FCN		3
#define IDLE_FCN	4

struct event_trace {
    fcnp   fcn_address;	/* Name of function to be traced		*/
    int    parameter_1;	/* Index for first parameter to be traced	*/
    int    parameter_2;	/* Index for second parameter to be traced	*/
    int    parameter_3;	/* Return value or index for third parameter	*/
    int    fcn_type;    /* Type of function: user, sys, comm or IO	*/
};

/*
 *  Maximum number of functions to event trace. 
 */
int _max_event_trace = 1000;

/*
 *  Maximum depth of nested functions
 */
int _max_nested_functions = 256;

extern void _cprobe();
extern void _crecv();
extern void _csend();
extern void _csendrecv();
extern void flushmsg();
extern void _flushmsg();
extern void _gcol();
extern void _gcolx();
extern void _gdhigh();
extern void _gihigh();
extern void _gshigh();
extern void _gdlow();
extern void _gilow();
extern void _gslow();
extern void _gdprod();
extern void _giprod();
extern void _gsprod();
extern void _gdsum();
extern void _gisum();
extern void _gssum();
extern void _giand();
extern void _gland();
extern void _gior();
extern void _glor();
extern void _gixor();
extern void _glxor();
extern void _gopf();
extern void _gopf_();
extern void _gsendx();
extern void _gsync();
extern void _hrecv();
extern void _hsend();
extern void _hsendrecv();
extern void _iprobe();
extern void _irecv();
extern void _isend();
extern void _isendrecv();
extern void _msgcancel();
extern void _msgdone();
extern void _msgwait();
extern void _cread();
extern void _cwrite();
extern void _eseek();
extern void _esize();
extern void _estat();
extern void _festat();
extern void _iodone();
extern void _iomode();
extern void _iowait();
extern void _iread();
extern void _iseof();
extern void _iwrite();
extern void _lsize();
extern void _restrictvol();
extern void _setiomode();
extern void _flick();
extern void _fork();
extern void _handler();
extern void _killcube();
extern void killproc();
extern void _killproc();
extern void _led();
extern void load();
extern void _load();
extern void _masktrap();
extern void waitall();
extern void _waitall();
extern void waitone();
extern void _waitone();
extern void access();
extern void alarm();
extern void brk();
extern void sbrk();
extern void chdir();
extern void chmod();
extern void chown();
extern void close();
extern void creat();
extern void dup();
extern void execl();
extern void execle();
extern void execlp();
extern void execv();
extern void execve();
extern void execvp();
extern void exit();
extern void gtty();
extern void ioctl();
extern void link();
extern void lseek();
extern void kill();
extern void mkdir();
extern void nice();
extern void open();
extern void pause();
extern void pipe();
extern void read();
extern void rmdir();
extern void signal();
extern void sigset();
extern void sighold();
extern void sigrelse();
extern void sigignore();
extern void sigpause();
extern void sigreturn();
extern void stat();
extern void fstat();
extern void statfs();
extern void fstatfs();
extern void sync();
extern void unlink();
extern void wait();
extern void write();

/*
 *  Default list of procedures that will be event traced.
 */
struct event_trace _event_trace_table[] = {
/* NX comm functions   parameter 1  parameter 2  parameter 3  fcn_type	*/
       _cprobe,                0,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _crecv,                 0,           2,    NO_PARAM,   COMM_FCN,
       _csend,                 0,           3,           2,   COMM_FCN,
       _csendrecv,             0,           3,           5,   COMM_FCN,
       flushmsg,               0,           1,    NO_PARAM,   COMM_FCN,
       _flushmsg,              0,           1,    NO_PARAM,   COMM_FCN,
       _gcol,                  1,           3,    NO_PARAM,   COMM_FCN,
       _gcolx,          NO_PARAM,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gdhigh,                1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gihigh,                1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gshigh,                1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gdlow,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gilow,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gslow,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gdprod,                1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _giprod,                1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gsprod,                1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gdsum,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gisum,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gssum,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _giand,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gland,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gior,                  1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _glor,                  1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gixor,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _glxor,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gopf,                  1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gopf_,                 1,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _gsendx,                2,           4,    NO_PARAM,   COMM_FCN,
       _gsync,          NO_PARAM,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _hrecv,                 0,           2,    NO_PARAM,   COMM_FCN,
       _hsend,                 0,           3,           2,   COMM_FCN,
       _hsendrecv,             0,           3,           5,   COMM_FCN,
       _iprobe,                0,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _irecv,                 0,           2,    NO_PARAM,   COMM_FCN,
       _isend,                 0,           3,           2,   COMM_FCN,
       _isendrecv,             0,           3,           5,   COMM_FCN,
       _msgcancel,             0,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _msgdone,               0,    NO_PARAM,    NO_PARAM,   COMM_FCN,
       _msgwait,               0,    NO_PARAM,    NO_PARAM,   COMM_FCN,
/* NX I/O functions    parameter 1  parameter 2  parameter 3  fcn_type	*/
       _cread,                 0,           2,    NO_PARAM,     IO_FCN,
       _cwrite,                0,           2,    NO_PARAM,     IO_FCN,
       _eseek,                 0,           2,    NO_PARAM,     IO_FCN,
       _esize,                 0,           2,    NO_PARAM,     IO_FCN,
       _estat,          NO_PARAM,    NO_PARAM,    NO_PARAM,     IO_FCN,
       _festat,                0,    NO_PARAM,    NO_PARAM,     IO_FCN,
       _iodone,                0,    NO_PARAM,    NO_PARAM,     IO_FCN,
       _iomode,                0,    NO_PARAM,    NO_PARAM,     IO_FCN,
       _iowait,                0,    NO_PARAM,    NO_PARAM,     IO_FCN,
       _iread,                 0,           2,    NO_PARAM,     IO_FCN,
       _iseof,                 0,    NO_PARAM,    NO_PARAM,     IO_FCN,
       _iwrite,                0,           2,    NO_PARAM,     IO_FCN,
       _lsize,                 0,           1,    NO_PARAM,     IO_FCN,
       _restrictvol,           0,           1,    NO_PARAM,     IO_FCN,
       _setiomode,             0,           1,    NO_PARAM,     IO_FCN,
/* NX SYS functions    parameter 1  parameter 2  parameter 3  fcn_type	*/
       _flick,          NO_PARAM,    NO_PARAM,    NO_PARAM,    IDLE_FCN,
       _fork,           NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       _handler,               0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       _killcube,              0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       killproc,               0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       _killproc,              0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       _led,            NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       load,                   1,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       _load,                  1,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       _masktrap,              0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       waitall,                0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       _waitall,               0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       waitone,                0,           2,           4,    SYS_FCN,
       _waitone,               0,           2,           4,    SYS_FCN,
/* UNIX functions      parameter 1  parameter 2  parameter 3  fcn_type	*/
       access,                 1,    NO_PARAM,    NO_PARAM,     IO_FCN,
       alarm,                  0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       brk,                    0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       sbrk,                   0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       chdir,           NO_PARAM,    NO_PARAM,    NO_PARAM,     IO_FCN,
       chmod,                  1,    NO_PARAM,    NO_PARAM,     IO_FCN,
       chown,                  1,           2,    NO_PARAM,     IO_FCN,
       close,                  0,    NO_PARAM,    NO_PARAM,     IO_FCN,
       creat,                  1,    NO_PARAM,    NO_PARAM,     IO_FCN,
       dup,                    0,    NO_PARAM,    NO_PARAM,     IO_FCN,
       execl,           NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       execle,          NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       execlp,          NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       execv,           NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       execve,          NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       execvp,          NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       exit,                   0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       gtty,                   0,    NO_PARAM,    NO_PARAM,     IO_FCN,
       ioctl,                  0,           1,    NO_PARAM,     IO_FCN,
       link,            NO_PARAM,    NO_PARAM,    NO_PARAM,     IO_FCN,
       lseek,                  0,           1,           2,     IO_FCN,
       kill,                   0,           1,    NO_PARAM,    SYS_FCN,
       mkdir,                  1,    NO_PARAM,    NO_PARAM,     IO_FCN,
       nice,                   0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       open,                   1,           2,    NO_PARAM,     IO_FCN,
       pause,           NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       pipe,                   0,    NO_PARAM,    NO_PARAM,     IO_FCN,
       read,                   0,           2,    NO_PARAM,     IO_FCN,
       rmdir,           NO_PARAM,    NO_PARAM,    NO_PARAM,     IO_FCN,
       signal,                 0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       sigset,                 0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       sighold,                0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       sigrelse,               0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       sigignore,              0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       sigpause,               0,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       sigreturn,       NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       stat,            NO_PARAM,    NO_PARAM,    NO_PARAM,     IO_FCN,
       fstat,                  0,    NO_PARAM,    NO_PARAM,     IO_FCN,
       statfs,                 2,           3,    NO_PARAM,     IO_FCN,
       fstatfs,                0,           3,    NO_PARAM,     IO_FCN,
       sync,            NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       unlink,          NO_PARAM,    NO_PARAM,    NO_PARAM,     IO_FCN,
       wait,            NO_PARAM,    NO_PARAM,    NO_PARAM,    SYS_FCN,
       write,                  0,           2,    NO_PARAM,     IO_FCN,
/* The table is terminated by a NULL entry 				*/
       (fcnp)0,                0,           0,           0,          0
};

