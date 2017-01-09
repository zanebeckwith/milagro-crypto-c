/**
 * @file test_output_functions.c
 * @author Alessandro Budroni
 * @brief Test output functions for debug
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
#include <string.h>
#include <stdlib.h>
#include "arch.h"
#include "amcl.h"
#include "utils.h"

extern int dup(int oldfd);
extern int dup2(int oldfd, int newfd);
extern int close(int fildes);
extern int fileno(FILE *stream);

#define LINE_LEN 1000

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

#if (CHOICE >= BN_CURVES)
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

    FP2_from_FPs(fp2,x,y);
}
#endif

int read_ECP(ECP *ecp, char* string)
{
    BIG x;
    char *end;
#if CURVETYPE!=MONTGOMERY
    BIG y;
    char *stringy;
    string++;
    stringy = strchr(string,',');
    if (stringy == NULL)
    {
        printf("ERROR unexpected test vector\n");
        exit(EXIT_FAILURE);
    }
    stringy[0] = '\0';
    stringy++;
    end = strchr(stringy,')');
#else
    string++;
    end = strchr(string,')');
#endif
    if (end == NULL)
    {
        printf("ERROR unexpected test vector\n");
        exit(EXIT_FAILURE);
    }
    end[0] = '\0';
    read_BIG(x,string);
#if CURVETYPE==MONTGOMERY
    return ECP_set(ecp,x);
#else
    read_BIG(y,stringy);
    return ECP_set(ecp,x,y);
#endif
}

#if (CHOICE >= BN_CURVES)
int read_ECP2(ECP2 *ecp2, char* stringx1)
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

    return ECP2_set(ecp2,&x,&y);
}
#endif

void read_OCT(octet *oct, char* string, int len)
{
    char buff[len-1];
    buff[len-1] = '\0';
    strncpy(buff,string,len-1);
    OCT_fromHex(oct,buff);
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        printf("usage: ./test_ecp2_arithmetics [path to test vector file] [path to output directory]\n");
        exit(EXIT_FAILURE);
    }

    int fd, len, ch1 = 0, ch2 = 0, i=0;
    fpos_t pos;
    FILE *testVectFile, *writtenFile;

    char line[LINE_LEN];
    char * linePtr = NULL;

    BIG big, bigaux;
    const char* BIGline = "BIG = ";
    const char* BIGrawline = "BIGraw = ";
    DBIG dbig;
    const char* DBIGline = "DBIG = ";
    BIG fp;
    const char* FPline = "FP = ";
    const char* FPrawline = "FPraw = ";
#if (CHOICE >= BN_CURVES)
    FP2 fp2, fp2aux;
    const char* FP2line = "FP2 = ";
    const char* FP2rawline = "FP2raw = ";
#endif
    ECP ecp;
    ECP ecpinf;
    const char* ECPline = "ECP = ";
    const char* ECPxyzline = "ECPxyz = ";
    const char* ECPinfline = "ECPinf = ";
    const char* ECPinfxyzline = "ECPinfxyz = ";
#if (CHOICE >= BN_CURVES)
    ECP2 ecp2;
    ECP2 ecp2inf;
    const char* ECP2line = "ECP2 = ";
    const char* ECP2xyzline = "ECP2xyz = ";
    const char* ECP2infline = "ECP2inf = ";
    const char* ECP2infxyzline = "ECP2infxyz = ";
#endif
    char octbuf[LINE_LEN];
    octet oct = {0,sizeof(octbuf),octbuf};
    const char* OCTline = "OCT = ";
    //const char* OCTstringline = "OCTstring = ";

    testVectFile = fopen(argv[1],"r");
    if (testVectFile == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    fgetpos(stdout, &pos);
    fd = dup(fileno(stdout));

    if(freopen(argv[2], "w", stdout) == NULL)
    {
        printf("ERROR redirecting stdout\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, testVectFile) != NULL)
    {
        i++;
        if (!strncmp(line,  BIGline, strlen(BIGline)))
        {
            len = strlen(BIGline);
            linePtr = line + len;
            read_BIG(big, linePtr);
            printf("%s",BIGline);
            BIG_output(big);
            printf("\n");
            printf("%s",BIGrawline);
            BIG_rawoutput(big);
            printf("\n\n");
        }
        if (!strncmp(line,  DBIGline, strlen(DBIGline)))
        {
            len = strlen(DBIGline);
            linePtr = line + len;
            read_DBIG(dbig, linePtr);
            printf("%s",DBIGline);
            BIG_doutput(dbig);
            printf("\n\n");
        }
        if (!strncmp(line,  FPline, strlen(FPline)))
        {
            len = strlen(FPline);
            linePtr = line + len;
            read_BIG(fp,linePtr);
            FP_nres(fp);
            printf("%s",FPline);
            FP_output(fp);
            printf("\n");
            printf("%s",FPrawline);
            FP_rawoutput(fp);
            printf("\n\n");
        }
#if (CHOICE >= BN_CURVES)
        if (!strncmp(line,  FP2line, strlen(FP2line)))
        {
            len = strlen(FP2line);
            linePtr = line + len;
            read_FP2(&fp2,linePtr);
            FP_nres(fp2.a);
            FP_nres(fp2.b);
            printf("%s",FP2line);
            FP2_output(&fp2);
            printf("\n");
            printf("%s",FP2rawline);
            FP2_rawoutput(&fp2);
            printf("\n\n");
        }
#endif
        if (!strncmp(line,  ECPline, strlen(ECPline)))
        {
            len = strlen(ECPline);
            linePtr = line + len;
            read_ECP(&ecp,linePtr);
            printf("%s",ECPline);
            ECP_output(&ecp);
            printf("%s",ECPxyzline);
            ECP_outputxyz(&ecp);
            BIG_copy(bigaux,ecp.x);
            BIG_inc(bigaux,100);
#if CURVETYPE!=MONTGOMERY
            ECP_set(&ecpinf,bigaux,ecpinf.y);
#else
            ECP_set(&ecpinf,bigaux);
#endif
            printf("%s",ECPinfline);
            ECP_output(&ecpinf);
            printf("%s",ECPinfxyzline);
            ECP_outputxyz(&ecpinf);
            printf("\n");
        }
#if (CHOICE >= BN_CURVES)
        if (!strncmp(line,  ECP2line, strlen(ECP2line)))
        {
            len = strlen(ECP2line);
            linePtr = line + len;
            read_ECP2(&ecp2,linePtr);
            printf("%s",ECP2line);
            ECP2_output(&ecp2);
            printf("%s",ECP2xyzline);
            ECP2_outputxyz(&ecp2);
            FP2_add(&fp2aux,&ecp2.x,&ecp2.y);
            ECP2_set(&ecp2inf,&fp2aux,&fp2aux);
            printf("%s",ECP2infline);
            ECP2_output(&ecp2inf);
            printf("%s",ECP2infxyzline);
            ECP2_outputxyz(&ecp2inf);
            printf("\n");
        }
#endif
        if (!strncmp(line,  OCTline, strlen(OCTline)))
        {
            len = strlen(OCTline);
            linePtr = line + len;
            read_OCT(&oct,linePtr,strlen(linePtr));
            printf("%s",OCTline);
            OCT_output(&oct);
            //printf("%s",OCTstringline);
            //OCT_output_string(&oct);
            //printf("\n");
        }
    }

    // Restore stdout
    fflush(stdout);
    dup2(fd, fileno(stdout));
    close(fd);
    clearerr(stdout);
    fsetpos(stdout, &pos);        /* for C9X */

    writtenFile = fopen(argv[2],"r");
    if (writtenFile == NULL)
    {
        printf("ERROR opening output file\n");
        exit(EXIT_FAILURE);
    }
    fclose(testVectFile);

    // Check the equality of the output with the test vector file

    testVectFile = fopen(argv[1],"r");
    if (testVectFile == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    ch1 = getc(testVectFile);
    ch2 = getc(writtenFile);

    while ((ch1 != EOF) && (ch2 != EOF) && (ch1 == ch2))
    {
        ch1 = getc(testVectFile);
        ch2 = getc(writtenFile);
    }

    if (ch1 != ch2)
    {
        printf("ERROR output does not match the expected one \n");
        exit(EXIT_FAILURE);
    }
    fclose(writtenFile);
    fclose(testVectFile);

    printf("SUCCESS TEST OUTPUT FUNCTIONS PASSED\n");
    exit(EXIT_SUCCESS);
}
