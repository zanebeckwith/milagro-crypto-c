/**
 * @file test_ecp_consistency.c
 * @author Alessandro Budroni
 * @brief Test for aritmetics with ECP
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

#define LINE_LEN 1000
#define MAX_STRING 400
#define PIN 1234
//#define DEBUG

void read_BIG(BIG A, char* string)
{
    int len;
    char bin[LINE_LEN];
    BIG_zero(A);
    len = strlen(string)+1;
    amcl_hex2bin(string,bin,len);
    len = (len-1)/2;;
    BIG_fromBytesLen(A,bin,len);
    BIG_norm(A);
}

int read_ECP(ECP *ecp, char* string)
{
    BIG x,y;

    char *stringy = strchr(string,':');
    stringy[0] = '\0';
    stringy++;
    read_BIG(x,string);
#if CURVETYPE==MONTGOMERY
    return ECP_set(ecp,x);
#else
    read_BIG(y,stringy);
    return ECP_set(ecp,x,y);
#endif
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_ecp_arithmetics [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int i=0, len=0;

    char line[LINE_LEN];
    char * linePtr = NULL;

    ECP ECPaux1, ECPaux2, inf;
    BIG BIGaux1, BIGaux2, BIGlazy1, BIGlazy2, Mod;

    char oct[len];
    octet OCTaux = {0,sizeof(oct),oct};

    ECP ecp1;
    const char* ECP1line = "ECP1 = ";
    ECP ecp2;
    const char* ECP2line = "ECP2 = ";
    ECP ecpsum;
    const char* ECPsumline = "ECPsum = ";
    ECP ecpneg;
    const char* ECPnegline = "ECPneg = ";
    ECP ecpsub;
    const char* ECPsubline = "ECPsub = ";
    ECP ecpdbl;
    const char* ECPdblline = "ECPdbl = ";
    BIG BIGscalar1;
    const char* BIGscalar1line = "BIGscalar1 = ";
    ECP ecpmul;
    const char* ECPmulline = "ECPmul = ";
    ECP ecppinmul;
    const char* ECPpinmulline = "ECPpinmul = ";
    BIG BIGscalar2;
    const char* BIGscalar2line = "BIGscalar2 = ";
    ECP ecpmul2;
    const char* ECPmul2line = "ECPmul2 = ";
    ECP ecpwrong;
    const char* ECPwrongline = "ECPwrong = ";
    ECP ecpinf;
    const char* ECPinfline = "ECPinf = ";
/*  ECP ecpeven;
    const char* ECPevenline = "ECPeven = ";
    ECP ecpodd;
    const char* ECPoddline = "ECPodd = ";*/

    ECP_inf(&inf);

    BIG_rcopy(Mod,Modulus);

    if(!ECP_isinf(&inf))
    {
        printf("ERROR setting ECP to infinity\n");
        exit(EXIT_FAILURE);
    }

    FILE *fp;
    fp = fopen(argv[1],"r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        i++;
        if (!strncmp(line,  ECP1line, strlen(ECP1line))) // get first test vector
        {
            len = strlen(ECP1line);
            linePtr = line + len;
            if(!read_ECP(&ecp1,linePtr) || ECP_isinf(&ecp1))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            ECP_get(BIGaux1,BIGaux2,&ecp1);
            FP_nres(BIGaux1);
            FP_nres(BIGaux2);
            FP_sqr(BIGaux2,BIGaux2);
            ECP_rhs(BIGaux1,BIGaux1);
            BIG_sub(BIGlazy1,BIGaux1,Mod); // in case of lazy reduction
            BIG_sub(BIGlazy2,BIGaux2,Mod); // in case of lazy reduction
            BIG_norm(BIGlazy1);
            BIG_norm(BIGlazy2);
            if ((BIG_comp(BIGaux1,BIGaux2)!=0) && (BIG_comp(BIGlazy1,BIGlazy2)!=0) && 
            	(BIG_comp(BIGaux1,BIGlazy2)!=0) && (BIG_comp(BIGlazy1,BIGaux2)!=0)) // test if y^2=x^3+Ax+B
            {
                printf("ERROR computing right hand side of equation ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            ECP_toOctet(&OCTaux,&ecp1);
            ECP_fromOctet(&ECPaux1,&OCTaux);
            if(!ECP_equals(&ECPaux1,&ecp1)) // test octet conversion
            {
                printf("ERROR converting ECP to/from OCTET, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  ECP2line, strlen(ECP2line))) //get second test vector
        {
            len = strlen(ECP2line);
            linePtr = line + len;
            if(!read_ECP(&ecp2,linePtr) || ECP_isinf(&ecp2))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  ECPsumline, strlen(ECPsumline)))
        {
            len = strlen(ECPsumline);
            linePtr = line + len;
            if(!read_ECP(&ecpsum,linePtr))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            ECP_copy(&ECPaux1,&ecp1);
            ECP_add(&ECPaux1,&ecp2);
            ECP_affine(&ECPaux1);
            if(!ECP_equals(&ECPaux1,&ecpsum)) // test addition P+Q
            {
                printf("ERROR adding two ECPs, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  ECPsubline, strlen(ECPsubline)))
        {
            len = strlen(ECPsubline);
            linePtr = line + len;
            if(!read_ECP(&ecpsub,linePtr))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            ECP_copy(&ECPaux1,&ecp1);
            ECP_sub(&ECPaux1,&ecp2);
            ECP_affine(&ECPaux1);
            if(!ECP_equals(&ECPaux1,&ecpsub)) // test subtraction P-Q
            {
                printf("ERROR computing negative of ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  ECPnegline, strlen(ECPnegline)))
        {
            len = strlen(ECPnegline);
            linePtr = line + len;
            if(!read_ECP(&ecpneg,linePtr))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            ECP_copy(&ECPaux1,&ecp1);
            ECP_neg(&ECPaux1);
            ECP_affine(&ECPaux1);
            if(!ECP_equals(&ECPaux1,&ecpneg))
            {
                printf("ERROR computing negative of ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  ECPdblline, strlen(ECPdblline)))
        {
            len = strlen(ECPdblline);
            linePtr = line + len;
            if(!read_ECP(&ecpdbl,linePtr))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            ECP_copy(&ECPaux1,&ecp1);
            ECP_dbl(&ECPaux1);
            ECP_affine(&ECPaux1);
            if(!ECP_equals(&ECPaux1,&ecpdbl))
            {
                printf("ERROR computing double of ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  BIGscalar1line, strlen(BIGscalar1line)))
        {
            len = strlen(BIGscalar1line);
            linePtr = line + len;
            read_BIG(BIGscalar1,linePtr);
        }
        if (!strncmp(line,  ECPmulline, strlen(ECPmulline)))
        {
            len = strlen(ECPmulline);
            linePtr = line + len;
            if(!read_ECP(&ecpmul,linePtr))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            ECP_copy(&ECPaux1,&ecp1);
            ECP_mul(&ECPaux1,BIGscalar1);
            ECP_affine(&ECPaux1);
            if(!ECP_equals(&ECPaux1,&ecpmul))
            {
                printf("ERROR computing multiplication of ECP by a scalar, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  ECPpinmulline, strlen(ECPpinmulline)))
        {
            len = strlen(ECPpinmulline);
            linePtr = line + len;
            if(!read_ECP(&ecppinmul,linePtr))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            ECP_copy(&ECPaux1,&ecp1);
            ECP_pinmul(&ECPaux1,PIN,14);
            ECP_affine(&ECPaux1);
            if(!ECP_equals(&ECPaux1,&ecppinmul))
            {
                printf("ERROR computing multiplication of ECP by small integer, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  BIGscalar2line, strlen(BIGscalar2line)))
        {
            len = strlen(BIGscalar2line);
            linePtr = line + len;
            read_BIG(BIGscalar2,linePtr);
        }
        if (!strncmp(line,  ECPmul2line, strlen(ECPmul2line)))
        {
            len = strlen(ECPmul2line);
            linePtr = line + len;
            if(!read_ECP(&ecpmul2,linePtr))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            ECP_copy(&ECPaux1,&ecp1);
            ECP_copy(&ECPaux2,&ecp2);
            ECP_mul2(&ECPaux1,&ECPaux2,BIGscalar1,BIGscalar2);
            ECP_affine(&ECPaux1);
            if(!ECP_equals(&ECPaux1,&ecpmul2))
            {
                printf("ERROR computing linear combination of 2 ECPs, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  ECPwrongline, strlen(ECPwrongline)))
        {
            len = strlen(ECPwrongline);
            linePtr = line + len;
            if(read_ECP(&ecpwrong,linePtr) || !ECP_isinf(&ecpwrong) || !ECP_equals(&ecpwrong,&inf))
            {
                printf("ERROR identifying wrong ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  ECPinfline, strlen(ECPinfline)))
        {
            len = strlen(ECPinfline);
            linePtr = line + len;
            if(read_ECP(&ecpinf,linePtr) || !ECP_isinf(&ecpinf) || !ECP_equals(&ecpinf,&inf))
            {
                printf("ERROR identifying infinite point ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  ECPevenline, strlen(ECPevenline)))
        {
            len = strlen(ECPevenline);
            linePtr = line + len;
            if(!read_ECP(&ecpeven,linePtr))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            BIG_copy(BIGaux1,ecp1.x);
            ECP_setx(&ECPaux1,BIGaux1,0);
            if(!ECP_equals(&ECPaux1,&ecpeven))
            {
                printf("ERROR computing ECP from coordinate x and with y even, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
        if (!strncmp(line,  ECPoddline, strlen(ECPoddline)))
        {
            len = strlen(ECPoddline);
            linePtr = line + len;
            if(!read_ECP(&ecpodd,linePtr))
            {
                printf("ERROR getting test vector input ECP, line %d\n",i);
                exit(EXIT_FAILURE);
            }
            BIG_copy(BIGaux1,ecp1.x);
            ECP_setx(&ECPaux1,BIGaux1,1);
            if(!ECP_equals(&ECPaux1,&ecpodd))
            {
                printf("ERROR computing ECP from coordinate x and with y odd, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
    }
    fclose(fp);

    printf("SUCCESS TEST ARITMETIC OF ECP PASSED\n");
    exit(EXIT_SUCCESS);
}


/*

#if CURVETYPE!=MONTGOMERY
#ifdef DEBUG
    FILE *fp;
    fp = fopen("../../mydata.txt", "a");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    BIG support, support1;
    BIG_rcopy(support,Modulus);
    //BIG_rcopy(support1,CURVE_B);

    fprintf(fp,"Choice: %s, Chunk: %s, Type: %s\n",argv[1],argv[2],argv[3]);
    fprintf(fp,"Modulus:");
    BIG_tofile(fp,support);
    fprintf(fp,",\n A: %d,\n",(int)CURVE_A);
    if(strcmp(argv[3],"MONTGOMERY") != 0)
    {
        fprintf(fp,"B: \n");
        //  BIG_tofile(fp,support1);
    }
    fprintf(fp,"\n----------------------------\n");
    fclose(fp);

void BIG_tofile(FILE* fp,BIG a)
{
    BIG b;
    int i,len;
    len=BIG_nbits(a);
    if (len%4==0) len/=4;
    else
    {
        len/=4;
        len++;
    }
    if (len<MODBYTES*2) len=MODBYTES*2;

    for (i=len-1; i>=0; i--)
    {
        BIG_copy(b,a);
        BIG_shr(b,i*4);
        fprintf(fp,"%01x",(unsigned int) b[0]&15);
    }
}
#endif
*/
