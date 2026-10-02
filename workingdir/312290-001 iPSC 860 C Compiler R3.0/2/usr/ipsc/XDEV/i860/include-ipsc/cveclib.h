/*
 *		INTEL CORPORATION PROPRIETARY INFORMATION
 *
 *  This software is supplied under the terms of a license
 *  agreement or nondisclosure agreement with Intel Corporation
 *  and may not be copied or disclosed except in accordance
 *  with the terms of that agreement.
 *
 *  cveclib.h 8.2 91/04/18 18:48:52
 *
 *  @(#)Release 3.3
 *  Copyright (c) 1988,1989,1990 Intel Corporation
 *
 */
typedef enum { FALSE=0, TRUE=-1 } logical;
typedef struct { float  r,i; } complex;
typedef struct { double r,i; } zcomplex;
extern complex cdotc(),cdotu(),csum();
extern zcomplex zdotc(),zdotu(),zsum();
extern double dasum(),ddot(),dsum(),dnrm2(),dzasum(),drandom();
extern float sasum(),sdot(),ssum(),snrm2(),scasum(),srandom();
extern int idamax(),idamin(),idmax(),idmin();
extern int isamax(),isamin(),ismax(),ismin();
extern int icount(),ilast(),ifirst();
extern logical lany();
