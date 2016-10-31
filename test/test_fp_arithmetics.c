/**
 * @file test_fp_arithmetics.c
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

#define LINE_LEN 10000
#define MAX_STRING 300
//#define DEBOUG

void read_BIG(BIG A, char* string)
{
    int len;
    char support[LINE_LEN];
    BIG_zero(A);
    len = strlen(string)+1;
    amcl_hex2bin(string,support,len);
    len = (len-1)/2;;
    BIG_fromBytesLen(A,support,len);
    BIG_norm(A);
}

void read_DBIG(DBIG A, char* string)
{
    int len;
    char support[LINE_LEN];
    BIG_dzero(A);
    len = strlen(string)+1;
    amcl_hex2bin(string,support,len);
    len = (len-1)/2;
    BIG_dfromBytesLen(A,support,len);
    BIG_dnorm(A);
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_FP_arithmetics [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int i = 0, len = 0, j = 0, k = 0;
    FILE *fp;

    char line[LINE_LEN];
    char * linePtr = NULL;

    BIG supp, supp1;

    BIG FP_1;
    const char* FP_1line = "FP_1 = ";
    BIG FP_2;
    const char* FP_2line = "FP_2 = ";
    BIG FP_1nres;
    const char* FP_1nresline = "FP_1nres = ";
    BIG FP_2nres;
    const char* FP_2nresline = "FP_2nres = ";
    BIG FPmulmod;
    const char* FPmulmodline = "FPmulmod = ";
    BIG FPsmallmul;
    const char* FPsmallmulline = "FPsmallmul = ";

/* Set to zero */
    BIG_zero(FP_1);
    BIG_zero(FP_2);

/* Testing equal function and set zero function */
    if(BIG_comp(FP_1,FP_2) && !FP_iszilch(FP_1) && !FP_iszilch(FP_2))
    {
        printf("ERROR comparing or setting zero FP\n");
        exit(EXIT_FAILURE);
    }

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

#ifdef DEBOUG
    BIG_rcopy(supp,Modulus);
    BIG_output(supp);printf("\n\n");
#endif

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        i++;
// Read first FP
        if (!strncmp(line,FP_1line, strlen(FP_1line)))
        {
            len = strlen(FP_1line);
            linePtr = line + len;
            read_BIG(FP_1,linePtr);
        }
// Read second FP
        if (!strncmp(line,FP_2line, strlen(FP_2line)))
        {
            len = strlen(FP_2line);
            linePtr = line + len;
            read_BIG(FP_2,linePtr);
        }
// Reduce first FP
        if (!strncmp(line,FP_1nresline, strlen(FP_1nresline)))
        {
            len = strlen(FP_1nresline);
            linePtr = line + len;
            read_BIG(FP_1nres,linePtr);
            BIG_copy(supp,FP_1);
            FP_nres(supp);
            FP_redc(supp);
            if(BIG_comp(supp,FP_1nres))
            {
                printf("ERROR Converts from BIG integer to n-residue form, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Reduce second FP
        if (!strncmp(line,FP_2nresline, strlen(FP_2nresline)))
        {
            len = strlen(FP_2nresline);
            linePtr = line + len;
            read_BIG(FP_2nres,linePtr);
            BIG_copy(supp,FP_2);
            FP_nres(supp);
            FP_redc(supp);
            if(BIG_comp(supp,FP_2nres))
            {
                printf("ERROR Converts from BIG integer to n-residue form, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Multiplication modulo
        if (!strncmp(line,FPmulmodline, strlen(FPmulmodline)))
        {
            len = strlen(FPmulmodline);
            linePtr = line + len;
            read_BIG(FPmulmod,linePtr);
            BIG_copy(supp,FP_1);BIG_copy(supp1,FP_2);
            FP_nres(supp);FP_nres(supp1);
            FP_mul(supp,supp,supp1);
            FP_redc(supp);
            if(BIG_comp(supp,FPmulmod))
            {
                printf("ERROR in multiplication and reduction by Modulo, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Small multiplication
        if (!strncmp(line,FPsmallmulline, strlen(FPsmallmulline)))
                {
                    len = strlen(FPsmallmulline);
                    linePtr = line + len;
                    read_BIG(FPsmallmul,linePtr);
                    FP_imul(supp,FP_1,0);
                    BIG_norm(supp);
                    if (!FP_iszilch(supp)) {
                        printf("ERROR in  multiplication by 0, line %d\n",i);
                    }
                    for (j = 1; j <= 5; ++j) {
                        FP_imul(supp,FP_1,j);
                        BIG_copy(supp1,FP_1);
                        for (k = 1; k < j; ++k) {
                            FP_add(supp1,supp1,FP_1);
                        }
                        BIG_norm(supp1);
                        if(BIG_comp(supp,supp1))
                        {
                            printf("ERROR in small multiplication or addition, line %d, multiplier %d\n",i,j);
                            exit(EXIT_FAILURE);
                        }
                    }
                    if(BIG_comp(supp,FPsmallmul) | BIG_comp(supp1,supp))
                    {
                        printf("ERROR in small multiplication, line %d\n",i);
                        exit(EXIT_FAILURE);
                    }
                }

    }

    printf("SUCCESS TEST ARITMETIC OF FP PASSED\n");
    exit(EXIT_SUCCESS);
}

