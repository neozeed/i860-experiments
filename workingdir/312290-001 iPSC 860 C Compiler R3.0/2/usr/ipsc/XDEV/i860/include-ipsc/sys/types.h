
/* types.h 9.2 91/08/29 10:23:51 */

/*      @(#)types.h	3.4 Lachman System V STREAMS TCP  source        */
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

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

/*	This Module contains Proprietary Information of Microsoft  */
/*	Corporation and should be treated as Confidential.	   */

#ident	"@(#)head.sys:types.h	1.5.1.2"

typedef	struct { int r[1]; } *	physadr;
typedef	long		daddr_t;	/* <disk address> type */
typedef	char *		caddr_t;	/* ?<core address> type */
typedef	unsigned char	unchar;
typedef	unsigned short	ushort;
typedef	unsigned int	uint;
typedef	unsigned long	ulong;
typedef	ushort		ino_t;		/* <inode> type */
typedef	short		cnt_t;		/* ?<count> type */
#ifndef __TIME_T
#define __TIME_T
typedef	long		time_t;		/* <time> type */
#endif
typedef	int		label_t[6];
typedef	short		dev_t;		/* <old device number> type */
typedef	long		off_t;		/* ?<offset> type */
typedef	unsigned long	paddr_t;	/* <physical address> type */
typedef	int		key_t;		/* IPC key type */
typedef	unsigned char	use_t;		/* use count for swap.  */
typedef	short		sysid_t;
typedef	short		index_t;
typedef	short		lock_t;		/* lock work for busy wait */
#ifndef __SIZE_T
#define __SIZE_T
typedef	unsigned int	size_t;		/* len param for string funcs */
#endif
typedef ushort		sel_t;		/* Selector type */

/*
 * New type from XENIX
 */
typedef	char *		faddr_t;	/* same as caddr_t for 8086/386 */

/* These u_ types are used for BSD compatibility */

typedef unsigned char   u_char;
typedef unsigned short  u_short;
typedef unsigned int    u_int;
typedef unsigned long   u_long;
