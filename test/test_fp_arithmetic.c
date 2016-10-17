/**
 * @file test_fp_arithmetic.c
 * @author Alessandro Budroni
 * @brief Test for aritmetics with FP
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


#include "arch.h"
#include "amcl.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef enum { false, true } bool;

int main()
{
    int i,j;
    char raw[256];
    csprng rng;

    BIG F,G,H,I;

    /* Set to zero */
    BIG_zero(F);
    BIG_zero(G);
    BIG_zero(H);
    BIG_zero(I);

    /* Testing equal function and set zero function */
    if(!FP_equals(G,F) && !FP_equals(H,I) && !FP_iszilch(F) && !FP_iszilch(G) && !FP_iszilch(H) && !FP_iszilch(I))
    {
        printf("ERROR comparing or setting zero FP\n");
        exit(EXIT_FAILURE);
    }

    /* Fake random source */
    RAND_clean(&rng);
    for (i=0;i<256;i++) raw[i]=(char)i;
    RAND_seed(&rng,256,raw);

    /* Initialise vector */
    for (i=0;i<NLEN;i++)
    {
         for(j=0;j<(int)sizeof(chunk);j++)
         {
            F[i] |= ((chunk) RAND_byte(&rng)) << 8*j;
         	H[i] |= ((chunk) RAND_byte(&rng)) << 8*j;
         	I[i] |= ((chunk) RAND_byte(&rng)) << 8*j;
         }
    }

    /* Testing coping function */
    BIG_copy(G,F);
    if(!FP_equals(G,F))
    {
        printf("ERROR testing coping FP\n");
        exit(EXIT_FAILURE);
    }

    /* Testing reducing */
    BIG_copy(G,F);
    FP_nres(G);
    FP_redc(G);
    if(!FP_equals(G,F))
    {
        printf("ERROR testing reducing FP\n");
        exit(EXIT_FAILURE);
    }

    /* Testing addition, subtraction */
    BIG_copy(G,F);
    FP_nres(G);
    FP_nres(H);
    FP_nres(F);
    FP_add(G,G,H);
    FP_sub(G,G,H);
    FP_sub(H,H,H);
    if(!FP_equals(G,F) && !FP_iszilch(H))
    {
        printf("ERROR testing addition/subtraction FP\n");
        exit(EXIT_FAILURE);
    }

    /* Testing small multiplication and division by 2 */
    BIG_copy(G,F);
    FP_nres(F);
    FP_nres(G);
    FP_imul(G,G,1073741824); // 2^30
    for (i=0;i<30;i++)
        FP_div2(G,G);
    if(!FP_equals(G,F))
    {
        printf("ERROR testing small multiplication and division by 2 FP\n");
        exit(EXIT_FAILURE);
    }

    /* Testing small square and square root */
    BIG_copy(G,F);
    FP_nres(F);
    FP_nres(G);
    for (i=0;i<1000;i++)
            FP_sqr(G,G);
    for (i=0;i<1000;i++)
        FP_sqrt(G,G);
    if(!FP_equals(G,F))
    {
        printf("ERROR testing squaring and root by 2 FP\n");
        exit(EXIT_FAILURE);
    }

    /* Test negative number */
    BIG_copy(G,F);
    FP_nres(G);
    FP_nres(F);
    FP_neg(G,G);
    FP_imul(G,G,-1);
    if(!FP_equals(G,F))
    {
        printf("ERROR testing negative number FP\n");
        exit(EXIT_FAILURE);
    }


    /* Test multiplication and inverse FP */
    BIG_copy(G,F);
    FP_nres(F);
    FP_nres(G);
    FP_nres(I);
    FP_mul(H,G,I);
    FP_inv(I,I);
    FP_mul(G,H,I);
    FP_inv(H,I);
    FP_mul(I,H,I);
    FP_one(H);
    if(!FP_equals(G,F) && !FP_equals(I,H))
    {
        printf("ERROR testing multiplication and inverse FP\n");
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS TEST ARITMETIC OF FP PASSED\n");
    exit(EXIT_SUCCESS);
}
