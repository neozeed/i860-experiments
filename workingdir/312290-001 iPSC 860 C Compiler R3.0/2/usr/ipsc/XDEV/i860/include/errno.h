/*      @(#)errno.h	3.4 Lachman System V STREAMS TCP  source        */
/*
 *      System V STREAMS TCP - Release 3.0
 *
 *      Copyright 1987, 1988, 1989 Lachman Associates, Incorporated (LAI)
 *
 *      All Rights Reserved.
 *
 *      System V STREAMS TCP was jointly developed by Lachman
 *      Associates and Convergent Technologies.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*	THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF AT&T	*/
/*	The copyright notice above does not evidence any   	*/
/*	actual or intended publication of such source code.	*/
#ifndef _ERRNO_H
#define _ERRNO_H


#ident	"@(#)head.sys:errno.h	1.3.1.1"

/*
 * Error codes
 */

#define	EPERM	1	/* Not super-user			*/
#define	ENOENT	2	/* No such file or directory		*/
#define	ESRCH	3	/* No such process			*/
#define	EINTR	4	/* interrupted system call		*/
#define	EIO	5	/* I/O error				*/
#define	ENXIO	6	/* No such device or address		*/
#define	E2BIG	7	/* Arg list too long			*/
#define	ENOEXEC	8	/* Exec format error			*/
#define	EBADF	9	/* Bad file number			*/
#define	ECHILD	10	/* No children				*/
#define	EAGAIN	11	/* No more processes			*/
#define	ENOMEM	12	/* Not enough core			*/
#define	EACCES	13	/* Permission denied			*/
#define	EFAULT	14	/* Bad address				*/
#define	ENOTBLK	15	/* Block device required		*/
#define	EBUSY	16	/* Mount device busy			*/
#define	EEXIST	17	/* File exists				*/
#define	EXDEV	18	/* Cross-device link			*/
#define	ENODEV	19	/* No such device			*/
#define	ENOTDIR	20	/* Not a directory			*/
#define	EISDIR	21	/* Is a directory			*/
#define	EINVAL	22	/* Invalid argument			*/
#define	ENFILE	23	/* File table overflow			*/
#define	EMFILE	24	/* Too many open files			*/
#define	ENOTTY	25	/* Not a typewriter			*/
#define	ETXTBSY	26	/* Text file busy			*/
#define	EFBIG	27	/* File too large			*/
#define	ENOSPC	28	/* No space left on device		*/
#define	ESPIPE	29	/* Illegal seek				*/
#define	EROFS	30	/* Read only file system		*/
#define	EMLINK	31	/* Too many links			*/
#define	EPIPE	32	/* Broken pipe				*/
#define	EDOM	33	/* Math arg out of domain of func	*/
#define	ERANGE	34	/* Math result not representable	*/
#define	ENOMSG	35	/* No message of desired type		*/
#define	EIDRM	36	/* Identifier removed			*/
#define	ECHRNG	37	/* Channel number out of range		*/
#define	EL2NSYNC 38	/* Level 2 not synchronized		*/
#define	EL3HLT	39	/* Level 3 halted			*/
#define	EL3RST	40	/* Level 3 reset			*/
#define	ELNRNG	41	/* Link number out of range		*/
#define	EUNATCH 42	/* Protocol driver not attached		*/
#define	ENOCSI	43	/* No CSI structure available		*/
#define	EL2HLT	44	/* Level 2 halted			*/
#define	EDEADLK	45	/* Deadlock condition.			*/
#define	ENOLCK	46	/* No record locks available.		*/

/* Convergent Error Returns */
#define EBADE	50	/* invalid exchange			*/
#define EBADR	51	/* invalid request descriptor		*/
#define EXFULL	52	/* exchange full			*/
#define ENOANO	53	/* no anode				*/
#define EBADRQC	54	/* invalid request code			*/
#define EBADSLT	55	/* invalid slot				*/
#define EDEADLOCK 56	/* file locking deadlock error		*/

#define EBFONT	57	/* bad font file fmt			*/

/* stream problems */
#define ENOSTR	60	/* Device not a stream			*/
#define ENODATA	61	/* no data (for no delay io)		*/
#define ETIME	62	/* timer expired			*/
#define ENOSR	63	/* out of streams resources		*/

#define ENONET	64	/* Machine is not on the network	*/
#define ENOPKG	65	/* Package not installed                */
#define EREMOTE	66	/* The object is remote			*/
#define ENOLINK	67	/* the link has been severed */
#define EADV	68	/* advertise error */
#define ESRMNT	69	/* srmount error */

#define	ECOMM	70	/* Communication error on send		*/
#define EPROTO	71	/* Protocol error			*/
#define	EMULTIHOP 74	/* multihop attempted */
#define	EDOTDOT 76	/* Cross mount point (not really error)*/
#define EBADMSG 77	/* trying to read unreadable message	*/

#define ENOTUNIQ 80	/* given log. name not unique */
#define EBADFD	 81	/* f.d. invalid for this operation */
#define EREMCHG	 82	/* Remote address changed */

/* shared library problems */
#define ELIBACC	83	/* Can't access a needed shared lib.	*/
#define ELIBBAD	84	/* Accessing a corrupted shared lib.	*/
#define ELIBSCN	85	/* .lib section in a.out corrupted.	*/
#define ELIBMAX	86	/* Attempting to link in too many libs.	*/
#define ELIBEXEC	87	/* Attempting to exec a shared library.	*/

/*
 *	System V STREAMS TCP
 */
/* Errors from 4.2 BSD picked up to support sockets */
/* Note that the numbers are different from 4.2 numbering */

#define TCPERR		90
/* non-blocking and interrupt i/o */
#define EWOULDBLOCK     (TCPERR+0)       /* Operation would block */
#define EINPROGRESS     (TCPERR+1)       /* Operation now in progress */
#define EALREADY        (TCPERR+2)       /* Operation already in progress */
/* ipc/network software */

/* argument errors */
#define ENOTSOCK        (TCPERR+3)       /* Socket operation on non-socket */
#define EDESTADDRREQ    (TCPERR+4)       /* Destination address required */
#define EMSGSIZE        (TCPERR+5)       /* Message too long */
#define EPROTOTYPE      (TCPERR+6)       /* Protocol wrong type for socket */
#define EPROTONOSUPPORT (TCPERR+7)       /* Protocol not supported */
#define ESOCKTNOSUPPORT (TCPERR+8)       /* Socket type not supported */
#define EOPNOTSUPP      (TCPERR+9)       /* Operation not supported on socket */
#define EPFNOSUPPORT    (TCPERR+10)      /* Protocol family not supported */
#define EAFNOSUPPORT    (TCPERR+11)      /* Address family not supported by protocol family */
#define EADDRINUSE      (TCPERR+12)      /* Address already in use */
#define EADDRNOTAVAIL   (TCPERR+13)      /* Can't assign requested address */

/* operational errors */
#define ENETDOWN        (TCPERR+14)      /* Network is down */
#define ENETUNREACH     (TCPERR+15)      /* Network is unreachable */
#define ENETRESET       (TCPERR+16)      /* Network dropped connection on reset */
#define ECONNABORTED    (TCPERR+17)      /* Software caused connection abort */
#define ECONNRESET      (TCPERR+18)      /* Connection reset by peer */
#define ENOBUFS         ENOSR            /* No buffer space available */
#define EISCONN         (TCPERR+20)      /* Socket is already connected */
#define ENOTCONN        (TCPERR+21)      /* Socket is not connected */
#define ESHUTDOWN       (TCPERR+22)      /* Can't send after socket shutdown */
#define ETOOMANYREFS    (TCPERR+23)      /* Too many references: can't splice */
#define ETIMEDOUT       (TCPERR+24)      /* Connection timed out */
#define ECONNREFUSED    (TCPERR+25)      /* Connection refused */


/* should be rearranged */
#define EHOSTDOWN       (TCPERR+26)      /* Host is down */
#define EHOSTUNREACH    (TCPERR+27)      /* No route to host */
#define ENOPROTOOPT     (TCPERR+28)      /* Protocol not available */

/* XENIX error numbers */
#define EUCLEAN	135	/* Structure needs cleaning */
#define ENOTNAM	137	/* Not a name file */
#define ENAVAIL	138	/* Not available */
#define EISNAM	139	/* Is a name file */
#define EREMOTEIO	140	/* Remote I/O error */
#define EINIT	141	/* Reserved for future */
#define EREMDEV	142	/* Error 142 */

/* avoid 255 (it's a -1 for a char ) */
/*  iPSC/2 error codes */

#define F_PSCERR 150
#define EQDRVERR	(F_PSCERR+0)	/* Internal driver error */
#define EQPBUF		(F_PSCERR+1)	/* Invalid buffer pointer */
#define EQBLEN		(F_PSCERR+2)	/* Buffer length exceeds allocation */
#define EQLEN		(F_PSCERR+3)	/* Invalid length */
#define EQTIME		(F_PSCERR+4)	/* Time limit exceeded */
#define EQMSGLONG	(F_PSCERR+5)	/* Received message too long for buffer */
#define EQPID		(F_PSCERR+6)	/* Invalid pid */
#define EQNODE		(F_PSCERR+7)	/* Invalid node */
#define EQTYPE		(F_PSCERR+8)	/* Invalid type */
#define EQMID		(F_PSCERR+9)	/* Invalid message id */
#define EQHND		(F_PSCERR+10)	/* Invalid handler type */
#define EQNOPROC	(F_PSCERR+11)	/* Out of process slots */
#define EQUSEPID	(F_PSCERR+12)	/* Pid already in use */
#define EQNOACT		(F_PSCERR+13)	/* No active process */
#define EQBADFIL	(F_PSCERR+14)	/* Invalid object file */
#define EQPARAM		(F_PSCERR+15)	/* Invalid parameter */
#define EQPFIL		(F_PSCERR+16)	/* Invalid file name pointer */
#define EQPCNODE	(F_PSCERR+17)	/* Invalid cnode pointer */
#define EQPCPID		(F_PSCERR+18)	/* Invalid cpid pointer */
#define EQPCCODE	(F_PSCERR+19)	/* Invalid ccode pointer */
#define EQPRIV		(F_PSCERR+20)	/* Privileged operation */
#define EQMEM		(F_PSCERR+21)	/* Not enough memory */
#define EQINVREC	(F_PSCERR+22)	/* Invalid loader record */
#define EQMSG		(F_PSCERR+23)	/* Invalid loader message */
#define EQNOMID		(F_PSCERR+24)	/* Too many requests */
#define EQSET		(F_PSCERR+25)	/* Pid already set */
#define EQNOSET		(F_PSCERR+26)	/* No pid defined */
#define EQCUBETABFULL	(F_PSCERR+27)	/* Internal cube usage limit */
#define EQCUBEEXISTS	(F_PSCERR+28)	/* Cubename already exists */
#define EQCUBENOTEXIST	(F_PSCERR+29)	/* Cubename does not exist */
#define EQCUBENOTATTCH	(F_PSCERR+30)	/* There is no attached cube */
#define EQUSOCK		(F_PSCERR+31)	/* Comm server out of unix sockets */
#define EQNETSOCK	(F_PSCERR+32)	/* Comm server out of net sockets */
#define EQTTY		(F_PSCERR+33)	/* Comm server out of ttys */
#define EQNOCUBES	(F_PSCERR+34)	/* There are no cubes allocated */
#define EQCUBENAMELEN	(F_PSCERR+35)	/* Cube name longer than 15 characters */
#define EQHOSTNAMELEN	(F_PSCERR+36)	/* Host name longer than 15 characters */
#define EQTYPENAMELEN	(F_PSCERR+37)	/* Cube type longer than 15 characters */
#define EQBADGLOBAL	(F_PSCERR+38)	/* Global value invalid */
#define EQRCSBUSY	(F_PSCERR+39)	/* Remote comm server busy, try again later */
#define EQINCMPREAD	(F_PSCERR+40)	/* Did not read header specified bytes */
#define EQNOCUBE	(F_PSCERR+41)	/* Cubetype not found */
#define EQLIFEBUSY	(F_PSCERR+42)	/* Internal cube usage limit */
#define EQNOCOMMSER	(F_PSCERR+43)	/* Commser not responding */
#define EQUSM		(F_PSCERR+44)	/* Invalid diagnostic channel usm id */
#define EQDIM		(F_PSCERR+45)	/* Invalid dimension */
#define EQMODE		(F_PSCERR+46)	/* Invalid diagnostic channel mode */
#define EQSTATUS	(F_PSCERR+47)	/* Invalid diagnostic channel status */
#define EQNOLL		(F_PSCERR+48)	/* Lifeline not responding */
#define EQBADNODE	(F_PSCERR+49)	/* Node not responding */
#define EQUSEVX		(F_PSCERR+50)	/* Vector extension in use by another process */
#define EQNOSRM		(F_PSCERR+51)	/* No SRM that matched your request was found */
#define EQMSGSHORT	(F_PSCERR+52)	/* Received message too short for buffer */
#define EQNOSYSLOG	(F_PSCERR+53)	/* No active syslog exists */
#define EQSYSLOG	(F_PSCERR+54)	/* Active syslog exists */
#define EQLOGFAIL	(F_PSCERR+55)	/* Cannot start syslog process */
#define EQBIGSYS	(F_PSCERR+56)	/* System too large for loading */
#define EQRRTTY		(F_PSCERR+57)	/* Cannot read from a remote terminal */
#define EQFSERVFAIL	(F_PSCERR+58)	/* Cannot start fserver process */
#define ECFPS		(F_PSCERR+59)	/* Seek to different file pointers */
#define ENFPS		(F_PSCERR+60)	/* Different file pointers */
#define EMIXIO		(F_PSCERR+61)	/* Mixed file operations */
#define EIMODE		(F_PSCERR+62)	/* Bad io mode number */
#define ESETIO		(F_PSCERR+63)	/* File is not synchronized */
#define ESRMIO		(F_PSCERR+64)	/* Not supported on the SRM */
#define ENOCFS		(F_PSCERR+65)	/* No CFS available */
#define EQCOMMBUF	(F_PSCERR+66)	/* Commser out of buffers */
#define EQESIZE		(F_PSCERR+67)	/* Invalid size */
#define EQNOVX		(F_PSCERR+68)	/* Vector extension not present */
#define ERDEOF		(F_PSCERR+69)	/* Attempt to read past end of file */
#define EQPATH		(F_PSCERR+70)	/* Path name too long */

extern int errno;

#endif
