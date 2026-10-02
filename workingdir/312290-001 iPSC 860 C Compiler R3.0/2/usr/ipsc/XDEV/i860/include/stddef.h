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

#ifndef _STDDEF_H
#define _STDDEF_H

typedef int ptrdiff_t;

#ifndef __SIZE_T
#define __SIZE_T
typedef unsigned int size_t;
#endif

typedef char wchar_t;

#define NULL    0
#define offsetof(s_name,m_name) (size_t)(char *)&(((s_name *)0)->m_name)

#endif
