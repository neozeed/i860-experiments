#include "nothing.h"

#ifndef SItype
#define SItype long int
#endif


SItype
__umodsi3 (a, b)
     unsigned SItype a, b;
{
  return a % b;
}
