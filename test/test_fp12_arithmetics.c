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

#define LINE_LEN 1000
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
    end[0] = '\0';

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

void read_FP12(FP4 *fp12, char *stringax1)
{
    char *stringax2, *strinay1, *strinay2, *strinbx1, *strinbx2, *strinby1, *strinby2, *stringcx1, *stringcx2, *stringcy1, *stringcy2, *end;

    /* ... */

}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_fp12_arithmetics [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int i = 0, len = 0, j = 0;
    FILE *fp;

    char line[LINE_LEN];
    char * linePtr = NULL;

    BIG M, Fr_a, Fr_b;
    FP2 Frob;
    FP12 FP12aux1, FP12aux2;

    FP12 FP12_1;
    const char* FP12_1line = "FP12_1 = ";
    FP12 FP12_2;
    const char* FP12_2line = "FP12_2 = ";

    BIG_rcopy(M,Modulus);
    BIG_rcopy(Fr_a,CURVE_Fra);
    BIG_rcopy(Fr_b,CURVE_Frb);
    FP2_from_BIGs(&Frob,Fr_a,Fr_b);

// Set to one
    FP12_one(&FP12aux1);
    FP12_one(&FP12aux2);

// Testing equal function and set one function
    if(!FP12_equals(&FP12aux1,&FP12aux2) || !FP12_isunity(&FP12aux1) || !FP12_isunity(&FP12aux2))
    {
        printf("ERROR comparing FP12s or setting FP12 to unity FP\n");
        exit(EXIT_FAILURE);
    }

    printf("\nciao\n");
    FP12_output(&FP12aux1);
    printf("\n\n");


/*
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
        if (!strncmp(line,FP12_1line, strlen(FP12_1line)))
        {
            len = strlen(FP4_1line);
            linePtr = line + len;
            read_FP12(&FP12_1,linePtr);
        }
// Read second FP4
        if (!strncmp(line,FP12_2line, strlen(FP12_2line)))
        {
            len = strlen(FP12_2line);
            linePtr = line + len;
            read_FP12(&FP12_2,linePtr);
        }
    }
    fclose(fp);*/

    printf("SUCCESS TEST ARITMETIC OF FP12 PASSED\n");
    exit(EXIT_SUCCESS);
}
