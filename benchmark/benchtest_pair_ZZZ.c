/**
 * @file test_mpin_sign.c
 * @author Mike Scott
 * @brief Test and benchmark pairing functions
 *
 * LICENSE
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "pair_ZZZ.h" /* Make sure and select a pairing-friendly curve in here! */

#define MIN_TIME 10.0
#define MIN_ITERS 10

int main()
{
    csprng RNG;
    BIG_XXX q,s,r,x,y,a,b,m;
    ECP_ZZZ P,G;
    FP2_YYY wx,wy,f;
    FP2_YYY c,cp,cpm1,cpm2,cr;
    ECP2_ZZZ Q,W;
    FP12_YYY g,w;
    unsigned long ran;

    int i,iterations;
    clock_t start;
    double elapsed;
    char pr[10];

    printf("Bechmark test PAIR - ZZZ Curve\n");

#if CHUNK==16
    printf("16-bit Build\n\n");
#endif
#if CHUNK==32
    printf("32-bit Build\n\n");
#endif
#if CHUNK==64
    printf("64-bit Build\n\n");
#endif

    time((time_t *)&ran);
    pr[0]=ran;
    pr[1]=ran>>8;
    pr[2]=ran>>16;
    pr[3]=ran>>24;
    for (i=4; i<10; i++) pr[i]=i;

    RAND_seed(&RNG,10,pr);

    BIG_XXX_rcopy(x,CURVE_Gx);

    BIG_XXX_rcopy(y,CURVE_Gy);
    ECP_ZZZ_set(&G,x,y);


    BIG_XXX_rcopy(r,CURVE_Order);
    BIG_XXX_randomnum(s,r,&RNG);
    ECP_ZZZ_copy(&P,&G);
    PAIR_ZZZ_G1mul(&P,r);

    if (!ECP_ZZZ_isinf(&P))
    {
        printf("FAILURE - rG!=O\n");
        exit(EXIT_FAILURE);
    }

    iterations=0;
    start=clock();
    do
    {
        ECP_ZZZ_copy(&P,&G);
        PAIR_ZZZ_G1mul(&P,s);

        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);
    elapsed=1000.0*elapsed/iterations;
    printf("G1 mul              - %8d iterations  ",iterations);
    printf(" %8.2lf ms per iteration\n",elapsed);


    BIG_XXX_rcopy(wx.a,CURVE_Pxa);
    FP_YYY_nres(wx.a);
    BIG_XXX_rcopy(wx.b,CURVE_Pxb);
    FP_YYY_nres(wx.b);
    BIG_XXX_rcopy(wy.a,CURVE_Pya);
    FP_YYY_nres(wy.a);
    BIG_XXX_rcopy(wy.b,CURVE_Pyb);
    FP_YYY_nres(wy.b);
    ECP2_ZZZ_set(&W,&wx,&wy);

    ECP2_ZZZ_copy(&Q,&W);
    ECP2_ZZZ_mul(&Q,r);

    if (!ECP2_ZZZ_isinf(&Q))
    {
        printf("FAILURE - rQ!=O\n");
        exit(EXIT_FAILURE);
    }

    iterations=0;
    start=clock();
    do
    {
        ECP2_ZZZ_copy(&Q,&W);
        PAIR_ZZZ_G2mul(&Q,s);

        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);
    elapsed=1000.0*elapsed/iterations;
    printf("G2 mul              - %8d iterations  ",iterations);
    printf(" %8.2lf ms per iteration\n",elapsed);

    PAIR_ZZZ_ate(&w,&Q,&P);
    PAIR_ZZZ_fexp(&w);

    FP12_YYY_copy(&g,&w);

    PAIR_ZZZ_GTpow(&g,r);

    if (!FP12_YYY_isunity(&g))
    {
        printf("FAILURE - g^r!=1\n");
        exit(EXIT_FAILURE);
    }

    iterations=0;
    start=clock();
    do
    {
        FP12_YYY_copy(&g,&w);
        PAIR_ZZZ_GTpow(&g,s);

        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);
    elapsed=1000.0*elapsed/iterations;
    printf("GT pow              - %8d iterations  ",iterations);
    printf(" %8.2lf ms per iteration\n",elapsed);

    BIG_XXX_rcopy(a,CURVE_Fra);
    BIG_XXX_rcopy(b,CURVE_Frb);
    FP2_YYY_from_BIGs(&f,a,b);

    BIG_XXX_rcopy(q,Modulus);

    BIG_XXX_copy(m,q);
    BIG_XXX_mod(m,r);

    BIG_XXX_copy(a,s);
    BIG_XXX_mod(a,m);

    BIG_XXX_copy(b,s);
    BIG_XXX_sdiv(b,m);

    FP12_YYY_copy(&g,&w);
    FP12_YYY_trace(&c,&g);

    FP12_YYY_frob(&g,&f);
    FP12_YYY_trace(&cp,&g);

    FP12_YYY_conj(&w,&w);
    FP12_YYY_mul(&g,&w);

    FP12_YYY_trace(&cpm1,&g);
    FP12_YYY_mul(&g,&w);
    FP12_YYY_trace(&cpm2,&g);

    iterations=0;
    start=clock();
    do
    {
        FP4_YYY_xtr_pow2(&cr,&cp,&c,&cpm1,&cpm2,a,b);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);
    elapsed=1000.0*elapsed/iterations;
    printf("GT pow (compressed) - %8d iterations  ",iterations);
    printf(" %8.2lf ms per iteration\n",elapsed);

    iterations=0;
    start=clock();
    do
    {
        PAIR_ZZZ_ate(&w,&Q,&P);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);
    elapsed=1000.0*elapsed/iterations;
    printf("PAIRing ATE         - %8d iterations  ",iterations);
    printf(" %8.2lf ms per iteration\n",elapsed);

    iterations=0;
    start=clock();
    do
    {
        FP12_YYY_copy(&g,&w);
        PAIR_ZZZ_fexp(&g);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);
    elapsed=1000.0*elapsed/iterations;
    printf("PAIRing FEXP        - %8d iterations  ",iterations);
    printf(" %8.2lf ms per iteration\n",elapsed);

    ECP_ZZZ_copy(&P,&G);
    ECP2_ZZZ_copy(&Q,&W);

    PAIR_ZZZ_G1mul(&P,s);
    PAIR_ZZZ_ate(&g,&Q,&P);
    PAIR_ZZZ_fexp(&g);

    ECP_ZZZ_copy(&P,&G);

    PAIR_ZZZ_G2mul(&Q,s);
    PAIR_ZZZ_ate(&w,&Q,&P);
    PAIR_ZZZ_fexp(&w);

    if (!FP12_YYY_equals(&g,&w))
    {
        printf("FAILURE - e(sQ,p)!=e(Q,sP) \n");
        exit(EXIT_FAILURE);
    }

    ECP2_ZZZ_copy(&Q,&W);
    PAIR_ZZZ_ate(&g,&Q,&P);
    PAIR_ZZZ_fexp(&g);

    PAIR_ZZZ_GTpow(&g,s);

    if (!FP12_YYY_equals(&g,&w))
    {
        printf("FAILURE - e(sQ,p)!=e(Q,P)^s \n");
        exit(EXIT_FAILURE);
    }

    printf("\nSUCCESS BENCHMARK TEST OF PAIR FUNCTIONS PASSED\n\n");
    exit(EXIT_SUCCESS);
}
