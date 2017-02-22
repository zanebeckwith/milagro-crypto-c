/**
 * @file test_mpin_vectors.c
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mpin.h"
#include "amcl.h"
#include "utils.h"

#define LINE_LEN 1000
#define DEBUG


extern int dup(int oldfd);
extern int dup2(int oldfd, int newfd);
extern int close(int fildes);
extern int fileno(FILE *stream);

void read_OCTET(octet* OCT, char* string)
{
    int len = strlen(string);
    char buff[len];
    strncpy(buff,string,len);
    char *end = strchr(buff,',');
    if (end == NULL)
    {
        printf("ERROR unexpected test vector\n");
        exit(EXIT_FAILURE);
    }
    end[0] = '\0';
    OCT_fromHex(OCT,buff);
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_mpin_vectors [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int i = 0, len = 0, rtn = 0;
    FILE *fp;

    char line[LINE_LEN];
    char * linePtr = NULL;

    char ss1[4*PFS], internalss1[4*PFS];
    octet SS1= {0,sizeof(ss1),ss1}, internalSS1= {0,sizeof(internalss1),internalss1};
    const char* SS1line = "SS1 = ";
    char ss2[4*PFS], internalss2[4*PFS];
    octet SS2= {0,sizeof(ss2),ss2}, internalSS2= {0,sizeof(internalss2),internalss2};
    const char* SS2line = "SS2 = ";
    int DATE = 0;
    const char* DATEline = "DATE = ";
    int PIN1 = 0;
    const char* PIN1line = "PIN1 = ";
    int PIN2 = 0;
    const char* PIN2line = "PIN2 = ";
    char server_secret[4*PFS];
    octet SERVER_SECRET= {0,sizeof(server_secret),server_secret};
    const char* SERVER_SECRETline = "SERVER_SECRET = ";
    char sec[2*PFS+1];
    octet SEC= {0,sizeof(sec),sec};
    const char* SECline = "SEC = ";
    char tp1[2*PFS+1];
    octet TP1= {0,sizeof(tp1),tp1};
    const char* TP1line = "TP1 = ";
    char tp2[2*PFS+1];
    octet TP2= {0,sizeof(tp2),tp2};
    const char* TP2line = "TP2 = ";
    char cs1[2*PFS+1];
    octet CS1= {0,sizeof(cs1),cs1};
    const char* CS1line = "CS1 = ";
    char cs2[2*PFS+1];
    octet CS2= {0,sizeof(cs2),cs2};
    const char* CS2line = "CS2 = ";
    char hash_mpin_id_hex[PFS];
    octet HASH_MPIN_ID_HEX= {0,sizeof(hash_mpin_id_hex),hash_mpin_id_hex};
    const char* HASH_MPIN_ID_HEXline = "HASH_MPIN_ID_HEX = ";
    char time_permit[2*PFS+1];
    octet TIME_PERMIT= {0,sizeof(time_permit),time_permit};
    const char* TIME_PERMITline = "TIME_PERMIT = ";
    char mpin_id_hex[PFS];
    octet MPIN_ID_HEX= {0,sizeof(mpin_id_hex),mpin_id_hex};
    const char* MPIN_ID_HEXline = "MPIN_ID_HEX = ";
    char token[2*PFS+1];
    octet TOKEN= {0,sizeof(token),token};;
    const char* TOKENline = "TOKEN = ";
    int SERVER_OUTPUT = 0;
    const char* SERVER_OUTPUTline = "SERVER_OUTPUT = ";
    char u[2*PFS+1];
    octet U= {0,sizeof(u),u};
    const char* Uline = "U = ";
    char v[2*PFS+1];
    octet V= {0,sizeof(v),v};
    const char* Vline = "V = ";
    char y[PFS];
    octet Y= {0,sizeof(y),y};
    const char* Yline = "Y = ";
    char x[PFS];
    octet X= {0,sizeof(x),x};
    const char* Xline = "X = ";
    char ut[2*PFS+1];
    octet UT= {0,sizeof(ut),ut};
    const char* UTline = "UT = ";
    char ms1[PFS];
    octet MS1= {0,sizeof(ms1),ms1};
    const char* MS1line = "MS1 = ";
    char ms2[PFS];
    octet MS2= {0,sizeof(ms2),ms2};
    const char* MS2line = "MS2 = ";
    char client_secret[2*PFS+1];
    octet CLIENT_SECRET= {0,sizeof(client_secret),client_secret};
    const char* CLIENT_SECRETline = "CLIENT_SECRET = ";


    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        i++;
// Read MS1
        if (!strncmp(line,MS1line, strlen(MS1line)))
        {
            len = strlen(MS1line);
            linePtr = line + len;
            read_OCTET(&MS1,linePtr);
        }
// Read MS2
        if (!strncmp(line,MS2line, strlen(MS2line)))
        {
            len = strlen(MS2line);
            linePtr = line + len;
            read_OCTET(&MS2,linePtr);
        }
// Read SS1
        if (!strncmp(line,SS1line, strlen(SS1line)))
        {
            len = strlen(SS1line);
            linePtr = line + len;
            read_OCTET(&SS1,linePtr);
// Generate first server secret shares
            rtn = MPIN_GET_SERVER_SECRET(&MS1,&internalSS1);
            if (rtn != 0)
            {
                printf("ERROR MPIN_GET_SERVER_SECRET(&MS1,&SS1), %d, line %d\n", rtn,i);
                exit(EXIT_FAILURE);
            }
            else if (!OCT_comp(&internalSS1,&SS1))
            {
#ifdef DEBUG
                OCT_output(&internalSS1);
                OCT_output(&SS1);
#endif
                printf("ERROR generating server secret, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Read SS2
        if (!strncmp(line,SS2line, strlen(SS2line)))
        {
            len = strlen(SS2line);
            linePtr = line + len;
            read_OCTET(&SS2,linePtr);
// Generate second server secret shares
            rtn = MPIN_GET_SERVER_SECRET(&MS2,&internalSS2);
            if (rtn != 0)
            {
                printf("ERROR MPIN_GET_SERVER_SECRET(&MS1,&SS2), %d, line %d\n", rtn,i);
                exit(EXIT_FAILURE);
            }
            else if (!OCT_comp(&internalSS2,&SS2))
            {
#ifdef DEBUG    
                OCT_output(&MS2);
                OCT_output(&internalSS2);
                OCT_output(&SS2);
#endif
                printf("ERROR generating server secret, line %d\n",i);
                exit(EXIT_FAILURE);
            }
        }
// Read DATE
        if (!strncmp(line,DATEline, strlen(DATEline)))
        {
            len = strlen(DATEline);
            linePtr = line + len;
            sscanf(linePtr,"%d\n",&DATE);
        }
// Read PIN1
        if (!strncmp(line,PIN1line, strlen(PIN1line)))
        {
            len = strlen(PIN1line);
            linePtr = line + len;
            sscanf(linePtr,"%d\n",&PIN1);
        }
// Read PIN2
        if (!strncmp(line,PIN2line, strlen(PIN2line)))
        {
            len = strlen(PIN2line);
            linePtr = line + len;
            sscanf(linePtr,"%d\n",&PIN2);
        }
// Read SERVER_SECRET
        if (!strncmp(line,SERVER_SECRETline, strlen(SERVER_SECRETline)))
        {
            len = strlen(SERVER_SECRETline);
            linePtr = line + len;
            read_OCTET(&SERVER_SECRET,linePtr);
        }
// Read SEC
        if (!strncmp(line,SECline, strlen(SECline)))
        {
            len = strlen(SECline);
            linePtr = line + len;
            read_OCTET(&SEC,linePtr);
        }
// Read TP1
        if (!strncmp(line,TP1line, strlen(TP1line)))
        {
            len = strlen(TP1line);
            linePtr = line + len;
            read_OCTET(&TP1,linePtr);
        }
// Read TP2
        if (!strncmp(line,TP2line, strlen(TP2line)))
        {
            len = strlen(TP2line);
            linePtr = line + len;
            read_OCTET(&TP2,linePtr);
        }
// Read CS1
        if (!strncmp(line,CS1line, strlen(CS1line)))
        {
            len = strlen(CS1line);
            linePtr = line + len;
            read_OCTET(&CS1,linePtr);
        }
// Read CS2
        if (!strncmp(line,CS2line, strlen(CS2line)))
        {
            len = strlen(CS2line);
            linePtr = line + len;
            read_OCTET(&CS2,linePtr);
        }
// Read HASH_MPIN_ID_HEX
        if (!strncmp(line,HASH_MPIN_ID_HEXline, strlen(HASH_MPIN_ID_HEXline)))
        {
            len = strlen(HASH_MPIN_ID_HEXline);
            linePtr = line + len;
            read_OCTET(&HASH_MPIN_ID_HEX,linePtr);
        }
// Read TIME_PERMIT
        if (!strncmp(line,TIME_PERMITline, strlen(TIME_PERMITline)))
        {
            len = strlen(TIME_PERMITline);
            linePtr = line + len;
            read_OCTET(&TIME_PERMIT,linePtr);
        }
// Read MPIN_ID_HEX
        if (!strncmp(line,MPIN_ID_HEXline, strlen(MPIN_ID_HEXline)))
        {
            len = strlen(MPIN_ID_HEXline);
            linePtr = line + len;
            read_OCTET(&MPIN_ID_HEX,linePtr);
        }
// Read TOKEN
        if (!strncmp(line,TOKENline, strlen(TOKENline)))
        {
            len = strlen(TOKENline);
            linePtr = line + len;
            read_OCTET(&TOKEN,linePtr);
        }
// Read U
        if (!strncmp(line,Uline, strlen(Uline)))
        {
            len = strlen(Uline);
            linePtr = line + len;
            read_OCTET(&U,linePtr);
        }  
// Read V
        if (!strncmp(line,Vline, strlen(Vline)))
        {
            len = strlen(Vline);
            linePtr = line + len;
            read_OCTET(&V,linePtr);
        }
// Read Y
        if (!strncmp(line,Yline, strlen(Yline)))
        {
            len = strlen(Yline);
            linePtr = line + len;
            read_OCTET(&Y,linePtr);
        }
// Read X
        if (!strncmp(line,Xline, strlen(Xline)))
        {
            len = strlen(Xline);
            linePtr = line + len;
            read_OCTET(&X,linePtr);
        }
// Read UT
        if (!strncmp(line,UTline, strlen(UTline)))
        {
            len = strlen(UTline);
            linePtr = line + len;
            read_OCTET(&UT,linePtr);
        }
// Read CLIENT_SECRET
        if (!strncmp(line,CLIENT_SECRETline, strlen(CLIENT_SECRETline)))
        {
            len = strlen(CLIENT_SECRETline);
            linePtr = line + len;
            read_OCTET(&CLIENT_SECRET,linePtr);
        }
// Read SERVER_OUTPUT
        if (!strncmp(line,SERVER_OUTPUTline, strlen(SERVER_OUTPUTline)))
        {
            len = strlen(SERVER_OUTPUTline);
            linePtr = line + len;
            sscanf(linePtr,"%d\n",&SERVER_OUTPUT);
        }
    }
    fclose(fp);

    printf("SUCCESS TEST MPIN PASSED\n");
    exit(EXIT_SUCCESS);
}



/*

    if (i % 24 == 0)
    {
        printf("\n%s%d\n",DATEline,DATE);
        printf("%s%d\n",PIN1line,PIN1);
        printf("%s%d\n",PIN2line,PIN2);
        printf("%s",MS1line);
        OCT_output(&MS1);
        printf("%s",MS2line);
        OCT_output(&MS2);
        printf("%s",SS1line);
        OCT_output(&SS1);
        printf("%s",SS2line);
        OCT_output(&SS2);
        printf("%s",SERVER_SECRETline);
        OCT_output(&SERVER_SECRET);
        printf("%s",MPIN_ID_HEXline);
        OCT_output(&MPIN_ID_HEX);
        printf("%s",HASH_MPIN_ID_HEXline);
        OCT_output(&HASH_MPIN_ID_HEX);
        printf("%s",CS1line);
        OCT_output(&CS1);
        printf("%s",CS2line);
        OCT_output(&CS2);
        printf("%s",CLIENT_SECRETline);
        OCT_output(&CLIENT_SECRET);
        printf("%s",TP1line);
        OCT_output(&TP1);
        printf("%s",TP2line);
        OCT_output(&TP2);
        printf("%s",TIME_PERMITline);
        OCT_output(&TIME_PERMIT);
        printf("%s",TOKENline);
        OCT_output(&TOKEN);
        printf("%s",Xline);
        OCT_output(&X);
        printf("%s",Uline);
        OCT_output(&U);
        printf("%s",UTline);
        OCT_output(&UT);
        printf("%s",SECline);
        OCT_output(&SEC);
        printf("%s",Yline);
        OCT_output(&Y);
        printf("%s",Vline);
        OCT_output(&V);
        printf("%s%d\n",SERVER_OUTPUTline,SERVER_OUTPUT);

    }


























*/