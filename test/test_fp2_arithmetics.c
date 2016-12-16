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

void read_FP2(FP2 *fp2, char* stringx)
{
    char *stringy;
    BIG x,y;

    stringy = strchr(stringx,',');
    stringy[0] = '\0';
    stringy++;

    read_BIG(x,stringx);
    read_BIG(y,stringy);
    
    FP2_from_BIGs(fp2,x,y);
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_fp2_arithmetics [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int i = 0, len = 0, j = 0;
    FILE *fp;

    char line[LINE_LEN];
    char * linePtr = NULL;

    BIG M;
    FP2 FP2aux1, FP2aux2;

    FP2 FP2_1;
    const char* FP2_1line = "FP2_1 = ";
    FP2 FP2_2;
    const char* FP2_2line = "FP2_2 = ";
    FP2 FP2add;
    const char* FP2addline = "FP2add = ";
    FP2 FP2neg;
    const char* FP2negline = "FP2neg = ";
    FP2 FP2sub;
    const char* FP2subline = "FP2sub = ";
    FP2 FP2conj;
    const char* FP2conjline = "FP2conj = ";
    BIG FPmul;
    const char* FPmulline = "FPmul = ";
    FP2 FP2pmul;
    const char* FP2pmulline = "FP2pmul = ";
    FP2 FP2imul;
    const char* FP2imulline = "FP2imul = ";
    FP2 FP2sqr;
    const char* FP2sqrline = "FP2sqr = ";

    BIG_rcopy(M,Modulus);

// Set to zero
    FP2_zero(&FP2aux1);
    FP2_zero(&FP2aux2);

// Testing equal function and set zero function
    if(!FP2_equals(&FP2aux1,&FP2aux2) || !FP2_iszilch(&FP2aux1) || !FP2_iszilch(&FP2aux2))
    {
        printf("ERROR comparing FP2s or setting FP2 to zero FP\n");
        exit(EXIT_FAILURE);
    }

// Set to one
    FP2_one(&FP2aux1);
    FP2_one(&FP2aux2);

// Testing equal function and set one function
if(!FP2_equals(&FP2aux1,&FP2aux2) || !FP2_isunity(&FP2aux1) || !FP2_isunity(&FP2aux2))
    {
        printf("ERROR comparing FP2s or setting FP2 to unity FP\n");
        exit(EXIT_FAILURE);
    }   


    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        i++;
// Read first FP2 and perform some tests
        if (!strncmp(line,FP2_1line, strlen(FP2_1line)))
        {
            len = strlen(FP2_1line);
            linePtr = line + len;
            read_FP2(&FP2_1,linePtr);
            FP2_cmove(&FP2aux1,&FP2_1,0);
            if(FP2_equals(&FP2aux1,&FP2_1) != 0)
            {
                printf("ERROR in conditional copy of FP2, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            FP2_cmove(&FP2aux1,&FP2_1,1);
            if(!FP2_equals(&FP2aux1,&FP2_1) != 0)
            {
                printf("ERROR in conditional copy of FP2, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            FP2_from_FPs(&FP2aux1,FP2_1.a,FP2_1.b);
            if(!FP2_equals(&FP2aux1,&FP2_1) != 0)
            {
                printf("ERROR in generating FP2 from two FPs, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            FP2_from_BIGs(&FP2aux1,FP2_1.a,FP2_1.b);
            FP_redc(FP2aux1.a);
            FP_redc(FP2aux1.b);
            if(!FP2_equals(&FP2aux1,&FP2_1) != 0)
            {
                printf("ERROR in generating FP2 from two BIGs, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            FP2_from_FP(&FP2aux1,FP2_1.a);
            FP2_copy(&FP2aux2,&FP2_1);
            BIG_zero(FP2aux2.b);
            if(!FP2_equals(&FP2aux1,&FP2aux2) != 0)
            {
                printf("ERROR in generating FP2 from one FP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            FP2_from_BIG(&FP2aux1,FP2_1.a);
            FP_redc(FP2aux1.a);
            FP2_copy(&FP2aux2,&FP2_1);
            BIG_zero(FP2aux2.b);
            if(!FP2_equals(&FP2aux1,&FP2aux2) != 0)
            {
                printf("ERROR in generating FP2 from one BIG, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Read second FP2
        if (!strncmp(line,FP2_2line, strlen(FP2_2line)))
        {
            len = strlen(FP2_2line);
            linePtr = line + len;
            read_FP2(&FP2_2,linePtr);
        }
// Addition test
        if (!strncmp(line,FP2addline, strlen(FP2addline)))
        {
            len = strlen(FP2addline);
            linePtr = line + len;
            read_FP2(&FP2add,linePtr);
            FP2_copy(&FP2aux1,&FP2_1);
            FP2_copy(&FP2aux2,&FP2_2);
            FP2_add(&FP2aux1,&FP2aux1,&FP2aux2);
            FP2_reduce(&FP2aux1);
            if(!FP2_equals(&FP2aux1,&FP2add))
            {
                printf("ERROR adding two FP2, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Negative an FP
        if (!strncmp(line,FP2negline, strlen(FP2negline)))
        {
            len = strlen(FP2negline);
            linePtr = line + len;
            read_FP2(&FP2neg,linePtr);
            FP2_copy(&FP2aux1,&FP2_1);
            FP2_neg(&FP2aux1,&FP2aux1);
            FP2_reduce(&FP2aux1);
            if(!FP2_equals(&FP2aux1,&FP2neg))
            {
                printf("ERROR in computing negative of FP2, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Subtraction test
        if (!strncmp(line,FP2subline, strlen(FP2subline)))
        {
            len = strlen(FP2subline);
            linePtr = line + len;
            read_FP2(&FP2sub,linePtr);
            FP2_copy(&FP2aux1,&FP2_1);
            FP2_copy(&FP2aux2,&FP2_2);
            FP2_sub(&FP2aux1,&FP2aux1,&FP2aux2);
            FP2_reduce(&FP2aux1);
            if(!FP2_equals(&FP2aux1,&FP2sub) != 0)
            {
                printf("ERROR subtraction between two FP2, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Compute conjugate
        if (!strncmp(line,FP2conjline, strlen(FP2conjline)))
        {
            len = strlen(FP2conjline);
            linePtr = line + len;
            read_FP2(&FP2conj,linePtr);
            FP2_copy(&FP2aux1,&FP2_1);
            FP2_conj(&FP2aux1,&FP2aux1);
            FP2_reduce(&FP2aux1);
            if(!FP2_equals(&FP2aux1,&FP2conj))
            {
                FP2_output(&FP2aux1);printf("\n\n");
                FP2_output(&FP2conj);printf("\n\n");
                printf("ERROR computing conjugate of FP2, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Read multiplicator
        if (!strncmp(line,FPmulline, strlen(FPmulline)))
        {
            len = strlen(FPmulline);
            linePtr = line + len;
            read_BIG(FPmul,linePtr);
        }
// Multiplication by FPmul
        if (!strncmp(line,FP2pmulline, strlen(FP2pmulline)))
        {
            len = strlen(FP2pmulline);
            linePtr = line + len;
            read_FP2(&FP2pmul,linePtr);
            FP2_pmul(&FP2aux1,&FP2_1,FPmul);
            FP_nres(FP2aux1.a);
            FP_nres(FP2aux1.b);
            if(!FP2_equals(&FP2aux1,&FP2pmul))
            {
                FP2_output(&FP2aux1);printf("\n\n");
                FP2_output(&FP2pmul);printf("\n\n");
                printf("ERROR in multiplication by BIG, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Multiplication by j = 1..10
        if (!strncmp(line,FP2imulline, strlen(FP2imulline)))
        {
            len = strlen(FP2imulline);
            linePtr = line + len;
            read_FP2(&FP2imul,linePtr);
            FP2_imul(&FP2aux1,&FP2_1,j);
            j++;
            FP2_reduce(&FP2aux1);
            if(!FP2_equals(&FP2aux1,&FP2imul))
            {
                FP2_output(&FP2aux1);printf("\n\n");
                FP2_output(&FP2imul);printf("\n\n");
                printf("ERROR in multiplication by small integer, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Square and square root
        if (!strncmp(line,FP2sqrline, strlen(FP2sqrline)))
        {
            len = strlen(FP2sqrline);
            linePtr = line + len;
            read_FP2(&FP2sqr,linePtr);
            FP2_copy(&FP2aux1,&FP2_1);
            FP2_sqr(&FP2aux1,&FP2aux1);
            FP2_reduce(&FP2aux1);
            if(!FP2_equals(&FP2aux1,&FP2sqr))
            {
                printf("ERROR in squaring FP2, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            /*FP_nres(supp);
            FP_sqrt(supp,supp);
            FP_redc(supp);
            if(BIG_comp(supp,FP_1))
            {
                printf("supp ");BIG_output(supp);printf("\n\n");
                printf("read ");BIG_output(FP_1);printf("\n\n");
                printf("ERROR square/square root consistency FP, line %d\n",i);
                exit(EXIT_FAILURE);
            }*/
        }
/* Reducing Modulo
        if (!strncmp(line,FPreduceline, strlen(FPreduceline)))
        {
            len = strlen(FPreduceline);
            linePtr = line + len;
            read_BIG(FPreduce,linePtr);
            BIG_copy(supp,FP_1);
            FP_reduce(supp);
            if(BIG_comp(supp,FPreduce))
            {
                printf("comp ");
                BIG_output(supp);
                printf("\n\n");
                printf("read ");
                BIG_output(FPreduce);
                printf("\n\n");
                printf("ERROR in reducing FP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Division by 2
        if (!strncmp(line,FPdiv2line, strlen(FPdiv2line)))
        {
            len = strlen(FPdiv2line);
            linePtr = line + len;
            read_BIG(FPdiv2,linePtr);
            BIG_copy(supp,FP_1);
            FP_redc(supp);
            FP_nres(supp);
            FP_div2(supp,supp);
            if(BIG_comp(supp,FPdiv2))
            {
                printf("comp ");
                BIG_output(supp);
                printf("\n\n");
                printf("read ");
                BIG_output(FPdiv2);
                printf("\n\n");
                printf("ERROR in division by 2, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Inverse Modulo and FP_one
        if (!strncmp(line,FPinvline, strlen(FPinvline)))
        {
            len = strlen(FPinvline);
            linePtr = line + len;
            read_BIG(FPinv,linePtr);
            BIG_copy(supp,FP_1);
            BIG_copy(supp1,FP_1);
            FP_nres(supp);
            FP_inv(supp,supp);
            FP_redc(supp);
            if(BIG_comp(supp,FPinv))
            {
                printf("comp ");
                BIG_output(supp);
                printf("\n\n");
                printf("read ");
                BIG_output(FPinv);
                printf("\n\n");
                printf("ERROR computing inverse modulo, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            FP_mul(supp,supp,supp1);
            FP_nres(supp);
            FP_reduce(supp);
            FP_one(supp1);
            FP_redc(supp1);
            if(BIG_comp(supp,supp1))
            {
                printf("comp1 ");
                BIG_output(supp);
                printf("\n\n");
                printf("comp2 ");
                BIG_output(supp1);
                printf("\n\n");
                printf("ERROR multipling FP and its inverse, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// modular exponentiation
        if (!strncmp(line,FPexpline, strlen(FPexpline)))
        {
            len = strlen(FPexpline);
            linePtr = line + len;
            read_BIG(FPexp,linePtr);
            BIG_copy(supp,FP_1);
            BIG_copy(supp1,FP_2);
            FP_nres(supp);
            FP_pow(supp,supp,supp1);
            FP_redc(supp);
            if(BIG_comp(supp,FPexp))
            {
                printf("supp ");
                BIG_output(supp);
                printf("\n\n");
                printf("read ");
                BIG_output(FPexp);
                printf("\n\n");
                printf("ERROR in modular exponentiation, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }*/
    }

    printf("SUCCESS TEST ARITMETIC OF FP PASSED\n");
    exit(EXIT_SUCCESS);
}
