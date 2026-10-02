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

#ifndef _LOCALE_H
#define _LOCALE_H

#include <stddef.h>

struct lconv {
  char *decimal_point;     /* "." */
  char *thousands_sep;     /* "" */
  char *grouping;          /* "" */
  char *int_curr_symbol;   /* "" */
  char *currency_symbol;   /* "" */
  char *mon_decimal_point; /* "" */
  char *mon_thousands_sep; /* "" */
  char *mon_grouping;      /* "" */
  char *positive_sign;     /* "" */
  char *negative_sign;     /* "" */
  char int_frac_digits;    /* CHAR_MAX */
  char frac_digits;        /* CHAR_MAX */
  char p_cs_precedes;      /* CHAR_MAX */
  char p_sep_by_space;     /* CHAR_MAX */
  char n_cs_precedes;      /* CHAR_MAX */
  char n_sep_by_space;     /* CHAR_MAX */
  char p_sign_posn;        /* CHAR_MAX */
  char n_sign_posn;        /* CHAR_MAX */
};

#define LC_ALL      (LC_COLLATE|  \
		     LC_CTYPE|    \
		     LC_MONETARY| \
		     LC_NUMERIC|  \
		     LC_TIME)
#define LC_COLLATE  (1<<0)
#define LC_CTYPE    (1<<1)
#define LC_MONETARY (1<<2)
#define LC_NUMERIC  (1<<3)
#define LC_TIME     (1<<4)

char         *setlocale  (int,
			  const char *);
struct lconv *localeconv (void);

#endif
