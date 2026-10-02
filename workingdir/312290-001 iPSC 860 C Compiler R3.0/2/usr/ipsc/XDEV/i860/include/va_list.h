/* 
* va_list.h
*
*      Copyright 1990, The Portland Group, Incorporated.
*      All rights reserved.
*
*        THE PORTLAND GROUP, INCORPORATED PROPRIETARY INFORMATION
* This software is supplied under the terms of a license agreement
* or nondisclosure agreement with The Portland Group and may not be
* copied or disclosed except in accordance with the terms of that
* agreement.
*/

#ifndef _VA_LIST
#define _VA_LIST
typedef struct {
	unsigned ireg_used;	/* How many int regs consumed 'til now? */
	unsigned freg_used;	/* How many flt regs consumed 'til now? */
	long *reg_base;		/* Address of where we stored the regs. */
	long *mem_ptr;		/* Address of memory args area. */
} va_list;
#endif
