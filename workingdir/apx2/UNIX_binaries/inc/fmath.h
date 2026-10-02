 /* This is the type definition for the complex data type, needed by C
    programmers for using the complex primitives in the scalar math library */

# ifndef __FMATH__
# define __FMATH__
typedef struct { float re, im } complex_t;
typedef struct { float sinfval, cosfval } sincosf_t;
typedef struct { double dsinval, dcosval } dsincos_t;

# define ccos  c_cos
# define cexp  c_exp
# define clog  c_log
# define csin  c_sin
# define csqrt c_sqrt
# define cabs  c_abs

#    ifdef __STDC__

       extern float acosf (float);
       extern float logf (float);
       extern float log10f (float);
       extern float asinf (float);
       extern float atanf (float);
       extern float atan2f (float,float);
       extern float cosf (float);
       extern float coshf (float);
       extern float expf (float);
       extern float sinf (float);
       extern sincosf_t sincosf (float);
       extern float sinhf (float);
       extern float sqrtf (float);
       extern float tanf (float);
       extern float tanhf (float);
       extern double acos (double);
       extern double log (double);
       extern double log10 (double);
       extern double asin (double);
       extern double atan (double);
       extern double atan2 (double, double);
       extern double cos (double);
       extern double cosh (double);
       extern double exp (double);
       extern double sin (double);
       extern dsincos_t sincos (double);
       extern double sinh (double);
       extern double sqrt (double);
       extern double tan (double);
       extern double tanh (double);
       extern complex_t c_cos (complex_t *);
       extern complex_t c_exp (complex_t *);
       extern complex_t c_log (complex_t *);
       extern complex_t c_sin (complex_t *);
       extern complex_t c_sqrt (complex_t *);
       extern float     c_abs (complex_t *);

#    else

       extern float acosf ();
       extern float logf ();
       extern float log10f ();
       extern float asinf ();
       extern float atanf ();
       extern float atan2f ();
       extern float cosf ();
       extern float coshf ();
       extern float expf ();
       extern float sinf ();
       extern sincosf_t sincosf ();
       extern float sinhf ();
       extern float sqrtf ();
       extern float tanf ();
       extern float tanhf ();
       extern double acos ();
       extern double log ();
       extern double log10 ();
       extern double asin ();
       extern double atan ();
       extern double atan2 ();
       extern double cos ();
       extern double cosh ();
       extern double exp ();
       extern double sin ();
       extern dsincos_t sincos ();
       extern double sinh ();
       extern double sqrt ();
       extern double tan ();
       extern double tanh ();
       extern complex_t c_cos ();
       extern complex_t c_exp ();
       extern complex_t c_log ();
       extern complex_t c_sin ();
       extern complex_t c_sqrt ();
       extern float     c_abs ();
  
#    endif
# endif
