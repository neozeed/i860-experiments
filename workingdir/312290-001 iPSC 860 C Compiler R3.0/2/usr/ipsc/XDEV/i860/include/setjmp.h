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

#ifndef _SETJMP_H
#define _SETJMP_H

#define _JBLEN	29

typedef int jmp_buf[_JBLEN];

int  setjmp  (jmp_buf);
void longjmp (jmp_buf,
	      int);

#endif
