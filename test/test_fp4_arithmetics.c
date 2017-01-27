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

void read_FP2(FP2 *fp2, char* stringx)
{
    char *stringy, *end;
    BIG x,y;

    stringx++;
    stringy = strchr(stringx,',');
    if (stringy == NULL)
    {
        printf("ERROR unexpected test vector\n");
        exit(EXIT_FAILURE);
    }
    stringy[0] = '\0';
    stringy++;
    end = strchr(stringy,']');
    if (end == NULL)
    {
        printf("ERROR unexpected test vector\n");
        exit(EXIT_FAILURE);
    }

    read_BIG(x,stringx);
    read_BIG(y,stringy);

    FP2_from_BIGs(fp2,x,y);
}

void read_FP4(FP4 *fp4, char* stringx1)
{
    char *stringx2, *stringy1, *stringy2, *end;
    BIG x1,x2,y1,y2;
    FP2 x,y;

    stringx1 += 2;
    stringx2 = strchr(stringx1,',');
    if (stringx2 == NULL)
    {
        printf("ERROR unexpected test vector\n");
        exit(EXIT_FAILURE);
    }
    stringx2[0] = '\0';
    stringx2 ++;
    stringy1 = strchr(stringx2,']');
    if (stringy1 == NULL)
    {
        printf("ERROR unexpected test vector\n");
        exit(EXIT_FAILURE);
    }
    stringy1[0] = '\0';
    stringy1 += 3;
    stringy2 = strchr(stringy1,',');
    if (stringy2 == NULL)
    {
        printf("ERROR unexpected test vector\n");
        exit(EXIT_FAILURE);
    }
    stringy2[0] = '\0';
    stringy2++;
    end = strchr(stringy2,']');
    if (end == NULL)
    {
        printf("ERROR unexpected test vector\n");
        exit(EXIT_FAILURE);
    }
    end[0] = '\0';

    read_BIG(x1,stringx1);
    read_BIG(x2,stringx2);
    read_BIG(y1,stringy1);
    read_BIG(y2,stringy2);

    FP2_from_BIGs(&x,x1,x2);
    FP2_from_BIGs(&y,y1,y2);

    FP4_from_FP2s(fp4,&x,&y);
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_fp2_arithmetics [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int i = 0, len = 0, j = 1;
    FILE *fp;

    char line[LINE_LEN];
    char * linePtr = NULL;

    BIG M;
    FP4 FP4aux1, FP4aux2;

    FP4 FP4_1;
    const char* FP4_1line = "FP4_1 = ";
    FP4 FP4_2;
    const char* FP4_2line = "FP4_2 = ";
    FP4 FP4add;
    const char* FP4addline = "FP4add = ";
    FP4 FP4neg;
    const char* FP4negline = "FP4neg = ";
    FP4 FP4sub;
    const char* FP4subline = "FP4sub = ";
    FP4 FP4conj;
    const char* FP4conjline = "FP4conj = ";
    FP4 FP4nconj;
    const char* FP4nconjline = "FP4nconj = ";
    FP2 FP2sc;
    const char* FP2scline = "FP2sc = ";
    FP4 FP4pmul;
    const char* FP4pmulline = "FP4pmul = ";
    FP4 FP4imul;
    const char* FP4imulline = "FP4imul = ";
    FP4 FP4sqr;
    const char* FP4sqrline = "FP4sqr = ";
    FP4 FP4mul;
    const char* FP4mulline = "FP4mul = ";
    FP4 FP4inv;
    const char* FP4invline = "FP4inv = ";
    FP4 FP4mulj;
    const char* FP4muljline = "FP4mulj = ";
    BIG BIGsc;
    const char* BIGscline = "BIGsc = ";
    FP4 FP4pow;
    const char* FP4powline = "FP4pow = ";

    BIG_rcopy(M,Modulus);

// Set to zero
    FP4_zero(&FP4aux1);
    FP4_zero(&FP4aux2);

// Testing equal function and set zero function
    if(!FP4_equals(&FP4aux1,&FP4aux2) || !FP4_iszilch(&FP4aux1) || !FP4_iszilch(&FP4aux2) || !FP4_isreal(&FP4aux1))
    {
        printf("ERROR comparing FP4s or setting FP4 to zero FP\n");
        exit(EXIT_FAILURE);
    }

// Set to one
    FP4_one(&FP4aux1);
    FP4_one(&FP4aux2);

// Testing equal function and set one function
    if(!FP4_equals(&FP4aux1,&FP4aux2) || !FP4_isunity(&FP4aux1) || !FP4_isunity(&FP4aux2) || !FP4_isreal(&FP4aux1))
    {
        printf("ERROR comparing FP4s or setting FP4 to unity FP\n");
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
// Read first FP4 and perform some tests
        if (!strncmp(line,FP4_1line, strlen(FP4_1line)))
        {
            len = strlen(FP4_1line);
            linePtr = line + len;
            read_FP4(&FP4_1,linePtr);
// test FP4_from_FP2s
            FP4_from_FP2s(&FP4aux1,&FP4_1.a,&FP4_1.b);
            if(!FP4_equals(&FP4aux1,&FP4_1))
            {
                //printf("ERROR in generating FP4 from two FP2s, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
// test FP4_from_FP2 and FP4_isreal
            FP4_from_FP2(&FP4aux1,&FP4_1.a);
            FP4_copy(&FP4aux2,&FP4_1);
            FP2_zero(&FP4aux2.b);
            if(!FP4_equals(&FP4aux1,&FP4aux2) || !FP4_isreal(&FP4aux1))
            {
                //printf("ERROR in generating FP4 from one FP2, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
        }
// Read second FP4
        if (!strncmp(line,FP4_2line, strlen(FP4_2line)))
        {
            len = strlen(FP4_2line);
            linePtr = line + len;
            read_FP4(&FP4_2,linePtr);
        }
// Addition test
        if (!strncmp(line,FP4addline, strlen(FP4addline)))
        {
            len = strlen(FP4addline);
            linePtr = line + len;
            read_FP4(&FP4add,linePtr);
            FP4_copy(&FP4aux1,&FP4_1);
            FP4_copy(&FP4aux2,&FP4_2);
            FP4_add(&FP4aux1,&FP4aux1,&FP4aux2);
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            if(!FP4_equals(&FP4aux1,&FP4add))
            {
                //printf("ERROR adding two FP4, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
        }
// Test negative of an FP4
        if (!strncmp(line,FP4negline, strlen(FP4negline)))
        {
            len = strlen(FP4negline);
            linePtr = line + len;
            read_FP4(&FP4neg,linePtr);
            FP4_copy(&FP4aux1,&FP4_1);
            FP4_neg(&FP4aux1,&FP4aux1);
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            if(!FP4_equals(&FP4aux1,&FP4neg))
            {
                //printf("ERROR in computing negative of FP4, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
        }
// Subtraction test
        if (!strncmp(line,FP4subline, strlen(FP4subline)))
        {
            len = strlen(FP4subline);
            linePtr = line + len;
            read_FP4(&FP4sub,linePtr);
            FP4_copy(&FP4aux1,&FP4_1);
            FP4_copy(&FP4aux2,&FP4_2);
            FP4_sub(&FP4aux1,&FP4aux1,&FP4aux2);
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            if(!FP4_equals(&FP4aux1,&FP4sub) != 0)
            {
                //printf("ERROR subtraction between two FP4, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
        }
// Test conjugate
        if (!strncmp(line,FP4conjline, strlen(FP4conjline)))
        {
            len = strlen(FP4conjline);
            linePtr = line + len;
            read_FP4(&FP4conj,linePtr);
            FP4_copy(&FP4aux1,&FP4_1);
            FP4_conj(&FP4aux1,&FP4aux1);
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            if(!FP4_equals(&FP4aux1,&FP4conj))
            {
                //printf("ERROR computing conjugate of FP4, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
        }
// Test negative conjugate
        if (!strncmp(line,FP4nconjline, strlen(FP4nconjline)))
        {
            len = strlen(FP4nconjline);
            linePtr = line + len;
            read_FP4(&FP4nconj,linePtr);
            FP4_copy(&FP4aux1,&FP4_1);
            FP4_nconj(&FP4aux1,&FP4aux1);
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            if(!FP4_equals(&FP4aux1,&FP4nconj))
            {
                //printf("ERROR computing negative conjugate of FP4, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
        }
// Read multiplicator
        if (!strncmp(line,FP2scline, strlen(FP2scline)))
        {
            len = strlen(FP2scline);
            linePtr = line + len;
            read_FP2(&FP2sc,linePtr);
        }
// Multiplication by FP2
        if (!strncmp(line,FP4pmulline, strlen(FP4pmulline)))
        {
            len = strlen(FP4pmulline);
            linePtr = line + len;
            read_FP4(&FP4pmul,linePtr);
            FP4_pmul(&FP4aux1,&FP4_1,&FP2sc);
            FP_nres(FP4aux1.a.a);
            FP_nres(FP4aux1.a.b);
            FP_nres(FP4aux1.b.a);
            FP_nres(FP4aux1.b.b);
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            if(!FP4_equals(&FP4aux1,&FP4pmul))
            {
                printf("\nFPaux1\n");
            	FP4_output(&FP4aux1);
            	printf("\n\nFP4pmul\n");
            	FP4_output(&FP4pmul);
            	printf("\n\n");

                //printf("ERROR in multiplication by FP2, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
            else
                printf("1\n\n");
        }
// Multiplication by j = 1..10
        if (!strncmp(line,FP4imulline, strlen(FP4imulline)))
        {
            len = strlen(FP4imulline);
            linePtr = line + len;
            read_FP4(&FP4imul,linePtr);
            FP4_imul(&FP4aux1,&FP4_1,j);
            j++;
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            if(!FP4_equals(&FP4aux1,&FP4imul))
            {
                printf("ERROR in multiplication by small integer, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Square test
        if (!strncmp(line,FP4sqrline, strlen(FP4sqrline)))
        {
            len = strlen(FP4sqrline);
            linePtr = line + len;
            read_FP4(&FP4sqr,linePtr);
            FP4_copy(&FP4aux1,&FP4_1);
            FP4_sqr(&FP4aux1,&FP4aux1);
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            /*printf("\nFP4aux1\n");
            FP4_output(&FP4aux1);
            printf("\n\nFP4sqr\n");
            FP4_output(&FP4sqr);
            printf("\n\n");*/
            if(!FP4_equals(&FP4aux1,&FP4sqr))
            {
                //printf("ERROR in squaring FP4, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
            else
                printf("1\n\n");
        }
// Multiplication between two FP4s
        if (!strncmp(line,FP4mulline, strlen(FP4mulline)))
        {
            len = strlen(FP4mulline);
            linePtr = line + len;
            read_FP4(&FP4mul,linePtr);
            FP4_mul(&FP4aux1,&FP4_1,&FP4_2);
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            /*printf("\nFP4aux1\n");
            FP4_output(&FP4aux1);
            printf("\n\nFP4mul\n");
            FP4_output(&FP4mul);
            printf("\n\n");*/
            if(!FP4_equals(&FP4aux1,&FP4mul))
            {
                //printf("ERROR in multiplication between two FP4s, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
            else
                printf("1\n\n");
        }
// Inverse
        if (!strncmp(line,FP4invline, strlen(FP4invline)))
        {
            len = strlen(FP4invline);
            linePtr = line + len;
            read_FP4(&FP4inv,linePtr);
            FP4_copy(&FP4aux1,&FP4_1);
            FP4_inv(&FP4aux1,&FP4aux1);
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            /*printf("\nFP4aux1\n");
            FP4_output(&FP4aux1);
            printf("\n\nFP4inv\n");
            FP4_output(&FP4inv);
            printf("\n\n");*/
            if(!FP4_equals(&FP4aux1,&FP4inv))
            {
                //printf("ERROR in computing inverse of FP4, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
            else
                printf("1\n\n");
        }
// Test multiplication of an FP4 instance by sqrt(1+sqrt(-1))
        if (!strncmp(line,FP4muljline, strlen(FP4muljline)))
        {
            len = strlen(FP4muljline);
            linePtr = line + len;
            read_FP4(&FP4mulj,linePtr);
            FP4_copy(&FP4aux1,&FP4_1);
            FP4_times_i(&FP4aux1);
            FP4_reduce(&FP4aux1);
            FP4_norm(&FP4aux1);
            if(!FP4_equals(&FP4aux1,&FP4mulj))
            {
                /*printf("\nFP4aux1\n");
                FP4_output(&FP4aux1);
                printf("\n\nFP4mulj\n");
                FP4_output(&FP4mulj);
                printf("\n\n");*/
                //printf("ERROR in  multiplication of an FP4 instance by sqrt(1+sqrt(-1)), line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
            else
                printf("1\n\n");
        }
// Read exponent
        if (!strncmp(line,BIGscline, strlen(BIGscline)))
        {
            len = strlen(BIGscline);
            linePtr = line + len;
            read_BIG(BIGsc,linePtr);
        }
// Raise FP4 by BIG power 
        if (!strncmp(line,FP4powline, strlen(FP4powline)))
        {
            len = strlen(FP4powline);
            linePtr = line + len;
            read_FP4(&FP4pow,linePtr);
            FP4_pow(&FP4aux1,&FP4_1,BIGsc);
            FP4_reduce(&FP4aux1);
            if(!FP4_equals(&FP4aux1,&FP4pow))
            {
                /*printf("\nFP4aux1\n");
                FP4_output(&FP4aux1);
                printf("\n\nFP4pow\n");
                FP4_output(&FP4pow);
                printf("\n\n");*/
                //printf("ERROR in raising FP2 by BIG power, line %d\n",i);
                printf("0\n\n");//exit(EXIT_FAILURE);
            }
            else
                printf("1\n\n");
        }
    }
    fclose(fp);

    printf("SUCCESS TEST ARITMETIC OF FP PASSED\n");
    exit(EXIT_SUCCESS);
}
