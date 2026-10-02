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

#ifndef _ASSERT_H
#define _ASSERT_H
void _assert(const char *,const char *,int);

#ifdef NDEBUG
#define assert(ignore) ((void)0)
#else
#define assert(value) (((value)? (void)0 : _assert(#value,__FILE__,__LINE__)))
#endif /* NDEBUG */

#endif /* _ASSERT_H */
