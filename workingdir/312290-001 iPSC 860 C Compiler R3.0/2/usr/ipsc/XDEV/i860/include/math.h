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

#ifndef _MATH_H
#define _MATH_H

#define HUGE_VAL (3.40282346638528860e+38F)

double acos  (double);
double asin  (double);
double atan  (double);
double atan2 (double,
	      double);
double cos   (double);
double sin   (double);
double tan   (double);
double cosh  (double);
double sinh  (double);
double tanh  (double);
double exp   (double);
double frexp (double,
	      int *);
double ldexp (double,
	      int);
double log   (double);
double log10 (double);
double modf  (double,
	      double *);
double pow   (double,
	      double);
double sqrt  (double);
double ceil  (double);
double fabs  (double);
double floor (double);
double fmod  (double,
	      double);
/* single precision analogues of above double precision functions */
float acosf  (float);
float asinf  (float);
float atanf  (float);
float atan2f (float,
	      float);
float cosf   (float);
float sinf   (float);
float tanf   (float);
float coshf  (float);
float sinhf  (float);
float tanhf  (float);
float expf   (float);
float logf   (float);
float log10f (float);
float modff  (float,
	      float *);
float powf   (float,
	      float);
float sqrtf  (float);
float ceilf  (float);
float fabsf  (float);
float floorf (float);
float fmodf  (float,
	      float);

/* non-ansi mandated functions */
extern double acosh    (double);
extern double asinh    (double);
extern double atanh    (double);
extern double cbrt     (double);
extern double expm1    (double);
extern double j0       (double);
extern double j1       (double);
extern double jn       (int, 
			double);
extern double y0       (double);
extern double y1       (double);
extern double yn       (int, 
			double);
extern double erf      (double);
extern double erfc     (double);
extern double hypot    (double,
			double);
extern double gamma    (double);
extern double lgamma   (double);
extern int finite      (double);
extern double copysign (double,
			double);
extern double logb     (double);
extern double log1p    (double);
extern double scalb    (double,
			int);
extern double rint     (double);
extern double scalb    (double,
			int);
extern double cbrt     (double);
extern double drem     (double,
			double);
#endif
