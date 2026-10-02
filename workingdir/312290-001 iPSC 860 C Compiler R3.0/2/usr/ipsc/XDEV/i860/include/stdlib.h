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

#ifndef _STDLIB_H
#define _STDLIB_H
#include <stddef.h>
  
typedef struct {
  int quot;
  int rem;
} div_t;

typedef struct {
  long int quot;
  long int rem;
} ldiv_t;

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define RAND_MAX ((int)0x7fff)

#define MB_CUR_MAX sizeof(wchar_t)

double   atof(const char *);
int      atoi(const char *);
long int atol(const char *);

double            strtod (const char *,
			  char **);
long int          strtol (const char *,
			  char **,
			  int);
unsigned long int strtoul(const char *,
			  char **,
			  int);

int  rand (void);
void srand(unsigned int);

void *calloc (size_t,
	      size_t);
void  free   (void *);
void *malloc (size_t);
void *realloc(void *,
	      size_t);

void  abort (void);
int   atexit(void (*)(void));
void  exit  (int);
char *getenv(const char *);
int   system(const char *);
     
void *bsearch(const void *, 
	      const void *, 
	      size_t, 
	      size_t,
	      int (*)(const void *, 
		      const void *));
void qsort   (void *, 
	      size_t,
	      size_t,
	      int (*)(const void *, 
		      const void *));
     
int      abs (int);
div_t    div (int, 
	      int);
long int labs(long int);
ldiv_t   ldiv(long int, 
	      long int);

int    mblen   (const char *, 
		size_t);
int    mbtowc  (wchar_t *,
		const char *,
		size_t);
int    wctomb  (char *,
		wchar_t);
size_t mbstowcs(wchar_t *,
		const char *,
		size_t);
size_t wcstombs(char *,
		const wchar_t *,
		size_t);

#endif
