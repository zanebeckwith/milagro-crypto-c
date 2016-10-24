/**
 * @file test_big_consistency.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "arch.h"
#include "amcl.h"
#include "utils.h"
#include "utils.h"

typedef enum { false, true } bool;

#define LINE_LEN 10000
#define MAX_STRING 300

void read_BIG(BIG A, char* string)
{
    int len;
    char support[LINE_LEN];
    BIG_zero(A);
    len = strlen(string)+1;
    amcl_hex2bin(string,support,len);
    len = strlen(support);
    BIG_fromBytesLen(A,support,len);
    BIG_norm(A);
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_BIG_arithmetics [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int i=0, len=0, ret=0;

    FILE *fp;

    char line[LINE_LEN];
    char * linePtr = NULL;

    BIG supp;

    BIG BIG1;
    const char* BIG1line = "BIG1 = ";
    BIG BIG2;
    const char* BIG2line = "BIG2 = ";
    BIG BIGsum;
    const char* BIGsumline = "BIGsum = ";
    BIG BIGsub;
    const char* BIGsubline = "BIGsub = ";
    BIG BIG1mod2;
    const char* BIG1mod2line = "BIG1mod2 = ";
    BIG BIG2mod1;
    const char* BIG2mod1line = "BIG2mod1 = ";

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    //bool readLine = false;

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        i++;
        if (!strncmp(line,  BIG1line, strlen(BIG1line)))
        {
            len = strlen(BIG1line);
            linePtr = line + len;
            read_BIG(BIG1,linePtr);
        }
// test comparison
        if (!strncmp(line,  BIG2line, strlen(BIG2line)))
        {
            len = strlen(BIG2line);
            linePtr = line + len;
            read_BIG(BIG2,linePtr);
            if (BIG_comp(BIG1,BIG2) < 0)
            {
                printf("ERROR comparing two BIGs, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// test addition
        if (!strncmp(line,  BIGsumline, strlen(BIGsumline)))
        {
            BIG_zero(supp);
            BIG_add(supp,BIG1,BIG2);
            len = strlen(BIGsumline);
            linePtr = line + len;
            read_BIG(BIGsum,linePtr);
            BIG_norm(supp);
            if (BIG_comp(BIGsum,supp) != 0)
            {
                printf("ERROR adding two BIGs, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// test subtraction
        if (!strncmp(line,  BIGsubline, strlen(BIGsubline)))
        {
            BIG_zero(supp);
            BIG_sub(supp,BIG1,BIG2);
            len = strlen(BIGsubline);
            linePtr = line + len;
            read_BIG(BIGsub,linePtr);
            BIG_norm(supp);
            if (BIG_comp(BIGsub,supp) != 0)
            {
                printf("ERROR subtracting two BIGs, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// test modulo 1
        if (!strncmp(line,  BIG1mod2line, strlen(BIG1mod2line)))
        {
            BIG_zero(supp);
            BIG_copy(supp,BIG1);
            ret = BIG_mod(supp,BIG2);
            len = strlen(BIG1mod2line);
            linePtr = line + len;
            read_BIG(BIG1mod2,linePtr);
            BIG_norm(supp);
            if (BIG_iszilch(BIG2) && (ret != -1))
            {
                printf("ERROR reducing modulo BIG, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            else if (!BIG_iszilch(BIG2) && BIG_comp(BIG1mod2,supp) != 0)
            {
                printf("ERROR reducing modulo BIG, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// test modulo 2
        if (!strncmp(line,  BIG2mod1line, strlen(BIG2mod1line)))
        {
            BIG_zero(supp);
            BIG_copy(supp,BIG2);
            BIG_mod(supp,BIG1);
            len = strlen(BIG2mod1line);
            linePtr = line + len;
            read_BIG(BIG2mod1,linePtr);
            BIG_norm(supp);
            if (BIG_comp(BIG2mod1,supp) != 0)
            {
                printf("ERROR reducing modulo BIG, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
    }

    printf("SUCCESS TEST ARITMETIC OF BIG PASSED\n");
    exit(EXIT_SUCCESS);
}
