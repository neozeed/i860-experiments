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

#ifndef _TIME_H
#define _TIME_H

#include <stddef.h>

#define CLOCKS_PER_SEC ((clock_t)10000000)

typedef double clock_t;

#ifndef __TIME_T
#define __TIME_T
typedef long int time_t;
#endif

struct	tm {
  int	tm_sec;
  int	tm_min;
  int	tm_hour;
  int	tm_mday;
  int	tm_mon;
  int	tm_year;
  int	tm_wday;
  int	tm_yday;
  int	tm_isdst;
};

clock_t clock (void);

double difftime (time_t,
		 time_t);

time_t mktime (struct tm *);
time_t time   (time_t *);

char *asctime (const struct tm *);
char *ctime   (const time_t *);

struct tm *gmtime   (const time_t *);
struct tm *localtime(const time_t *);

size_t strftime (char *,
		 size_t,
		 const char *,
		 const struct tm *);

#ifndef __STRICT_ANSI__
extern long timezone, altzone;
#endif
#endif
