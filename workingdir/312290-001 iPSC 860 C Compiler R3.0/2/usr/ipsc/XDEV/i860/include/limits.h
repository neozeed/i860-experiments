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

#ifndef _LIMITS_H
#define _LIMITS_H

   /* Number of bits in a storage unit */
#define CHAR_BIT 8
   /* Maximum char */
#define CHAR_MAX 127
   /* Minimum char */
#define CHAR_MIN (-128)
   /* Maximum signed char */
#define SCHAR_MAX 127
   /* Minimum signed char */
#define SCHAR_MIN (-128)
   /* Maximum unsigned char (minimum is always 0) */
#define UCHAR_MAX 255
   /* Maximum short */
#define SHRT_MAX 32767
   /* Minimum short */
#define SHRT_MIN (-32768)
   /* Maximum int */
#define INT_MAX 2147483647
   /* Minimum int */
#define INT_MIN (-2147483648)
   /* Maximum long */
#define LONG_MAX 2147483647L
   /* Minimum long */
#define LONG_MIN (-2147483648L)
   /* Maximum unsigned short (minimum is always 0) */
#define USHRT_MAX 65535U
   /* Maximum unsigned int (minimum is always 0) */
#define UINT_MAX 4294967295U
   /* Maximum unsigned long (minimum is always 0) */
#define ULONG_MAX 4294967295UL

#ifndef __STRICT_ANSI__
#define PATH_MAX 256
#endif
#endif
