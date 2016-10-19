/**
 * @file test_BIG_arithmetic.c
 * @author Alessandro Budroni
 * @brief Test for aritmetics with BIG
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

int main()
{
    int i;
    char raw[256], bytes[MODBYTES];
    csprng rng;

    BIG F,G,H;
    DBIG DF,DG;

    /* Fake random source */
    RAND_clean(&rng);
    for (i=0;i<256;i++) raw[i]=(char)i;
    RAND_seed(&rng,256,raw);

    /* Set to zero */
    BIG_zero(F);
    BIG_zero(G);

    /* Testing equal function and set zero function */
    if(BIG_comp(G,F) | !BIG_iszilch(F) | !BIG_iszilch(G))
    {
        printf("ERROR comparing or setting zero BIG\n");
        exit(EXIT_FAILURE);
    }

    /* Testing coping and equal function */
    BIG_random(F,&rng);
    BIG_copy(G,F);
    if(BIG_comp(G,F))
    {
        printf("ERROR testing coping and equal BIG\n");
        exit(EXIT_FAILURE);
    }

    /* Testing addition, subtraction */
    BIG_random(F,&rng);
    BIG_random(H,&rng);
    BIG_copy(G,F);
    BIG_add(G,G,H);
    BIG_sub(G,G,H);
    BIG_sub(H,H,H);
    if(BIG_comp(G,F) | !BIG_iszilch(H))
    {
        printf("ERROR testing addition/subtraction BIG\n");
        exit(EXIT_FAILURE);
    }

    /* Testing small multiplication and division by 3 */
    for (i=0;i<100;i++)
    {
        BIG_random(F,&rng);
    	BIG_copy(G,F);
        BIG_imul(G,G,3);
        BIG_div3(G);
        if(BIG_comp(G,F))
            {
                printf("ERROR testing small multiplication and division by 3 BIG\n");
                exit(EXIT_FAILURE);
            }
    }

    /* Testing square  */
    for (i=0;i<100;i++)
    {
        BIG_random(F,&rng);
        BIG_copy(G,F);
        BIG_sqr(DG,G);
        BIG_mul(DF,F,F);
        if(BIG_dcomp(DG,DF))
        {
        	printf("ERROR testing square BIG\n");
        	exit(EXIT_FAILURE);
        }
    }

    /* Testing from and to bytes conversion  */
    for (i=0;i<100;i++)
    {
        BIG_random(F,&rng);
        BIG_copy(G,F);
        BIG_toBytes(bytes,G);
        BIG_fromBytes(G,bytes);
        if(BIG_comp(G,F))
        {
            printf("ERROR testing from and to bytes conversion BIG\n");
            exit(EXIT_FAILURE);
        }
    }

    /* Testing small increment and decrement  */
    for (i=0;i<100;i++)
    {
        BIG_random(F,&rng);
        BIG_copy(G,F);
        BIG_inc(G,i);
        BIG_dec(G,i);
        if(BIG_comp(G,F))
        {
            printf("ERROR testing small increment and decrement BIG\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("SUCCESS TEST ARITMETIC OF BIG PASSED\n");
    exit(EXIT_SUCCESS);
}
