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

#ifndef _CTYPEH
#define _CTYPEH
#define _UPPER          0001
#define _LOWER          0002
#define _DIGIT          0004
#define _SPACE          0010
#define _PUNCT          0020
#define _CONTROL        0040
#define _BLANK          0100
#define _HEXDIGIT       0200

extern unsigned char _ctype[];

int isalnum(int);
int isalpha(int);
int isascii(int);
int iscntrl(int);
int isdigit(int);
int isgraph(int);
int islower(int);
int isprint(int);
int ispunct(int);
int isspace(int);
int isupper(int);
int isxdigit(int);
int tolower(int);
int toupper(int);

#define isalnum(ch) ((_ctype+1)[ch]&(_UPPER|_LOWER|_DIGIT))
#define isalpha(ch) ((_ctype+1)[ch]&(_UPPER|_LOWER))
#define isascii(ch) (!((ch) & ~0177))
#define iscntrl(ch) ((_ctype+1)[ch]&(_CONTROL))
#define isdigit(ch) ((_ctype+1)[ch]&(_DIGIT))
#define isgraph(ch) ((_ctype+1)[ch]&(_UPPER|_LOWER|_DIGIT|_PUNCT))
#define islower(ch) ((_ctype+1)[ch]&(_LOWER))
#define isprint(ch) ((_ctype+1)[ch]&(_PUNCT|_UPPER|_LOWER|_DIGIT|_BLANK))
#define ispunct(ch) ((_ctype+1)[ch]&(_PUNCT))
#define isspace(ch) ((_ctype+1)[ch]&(_SPACE))
#define isupper(ch) ((_ctype+1)[ch]&(_UPPER))
#define isxdigit(ch) ((_ctype+1)[ch]&(_DIGIT|_HEXDIGIT))
#define tolower(ch) ((_ctype+258)[ch])
#define toupper(ch) ((_ctype+258)[ch])
#endif





