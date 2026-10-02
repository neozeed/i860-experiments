/* 
* stdarg.h
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

#ifndef _STDARG_H
#define _STDARG_H	

#include <va_list.h>

extern void  __i860_builtin_va_start(va_list *);
extern void *__builtin_va_arg();

#define va_start(ap,parm) __i860_builtin_va_start(&ap)
#define va_arg(ap,type) (*(type *)__builtin_va_arg(&ap, (type *)0))

#define va_end(list)

#endif
