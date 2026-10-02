/*
 *        INTEL CORPORATION PROPRIETARY INFORMATION
 *
 *  This software is supplied under the terms of a license
 *  agreement or nondisclosure agreement with Intel Corporation
 *  and may not be copied or disclosed except in accordance
 *  with the terms of that agreement.
 *
 * %M% %I% %D% %U%
 *
 */

#ifndef _SIGNAL_H
#define _SIGNAL_H

typedef int sig_atomic_t;

#define SIG_ERR	(void(*)())-1
#define	SIG_DFL	(void(*)())0
#define	SIG_IGN	(void (*)())1
#define SIG_HOLD (void(*)())2

#define	SIGHUP	 1
#define	SIGINT	 2
#define	SIGQUIT	 3
#define	SIGILL	 4
#define	SIGTRAP	 5
#define SIGABRT  6
#define	SIGEMT	 7
#define	SIGFPE	 8
#define	SIGKILL	 9
#define	SIGBUS	 10
#define	SIGSEGV	 11
#define	SIGSYS	 12
#define	SIGPIPE	 13
#define	SIGALRM	 14
#define	SIGTERM	 15
#define	SIGUSR1	 16
#define	SIGUSR2	 17
#define	SIGCLD	 18
#define	SIGPWR	 19
#define SIGWINCH 20
#define SIGPOLL  22

#define NSIG     23
#define MAXSIG   32

void (*signal (int,
	       void (*)(int)))(int);
int    raise  (int);

#endif
