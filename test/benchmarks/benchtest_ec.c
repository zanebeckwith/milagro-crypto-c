/**
 * @file test_mpin_sign.c
 * @author Mike Scott
 * @brief Test and benchmark elliptic curve
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
#include <time.h>

#include "amcl.h"
#include "rsa.h"

#define MIN_TIME 10.0
#define MIN_ITERS 10

int main()
{
    csprng RNG;
    BIG s,r,x,y;
    ECP P,G;
    FP12 g;
    int i,iterations;
    clock_t start;
    double elapsed;
    char pr[10];
    unsigned long ran;
    rsa_public_key pub;
    rsa_private_key priv;
    char m[RFS],d[RFS],c[RFS];
    octet M= {0,sizeof(m),m};
    octet D= {0,sizeof(d),d};
    octet C= {0,sizeof(c),c};

#if CHOICE==NIST256
    printf("NIST256 Curve\n");
#endif
#if CHOICE==C25519
    printf("C25519 Curve\n");
#endif
#if CHOICE==BRAINPOOL
    printf("BRAINPOOL Curve\n");
#endif
#if CHOICE==ANSSI
    printf("ANSSI Curve\n");
#endif
#if CHOICE==MF254
    printf("MF254 Curve\n");
#endif
#if CHOICE==MS255
    printf("MS255 Curve\n");
#endif
#if CHOICE==MF256
    printf("MF256 Curve\n");
#endif
#if CHOICE==MS256
    printf("MS256 Curve\n");
#endif
#if CHOICE==HIFIVE
    printf("HIFIVE Curve\n");
#endif
#if CHOICE==GOLDILOCKS
    printf("GOLDILOCKS Curve\n");
#endif
#if CHOICE==NIST384
    printf("NIST384 Curve\n");
#endif
#if CHOICE==C41417
    printf("C41417 Curve\n");
#endif
#if CHOICE==NIST521
    printf("NIST521 Curve\n");
#endif

#if CHOICE==BN254
    printf("BN254 Curve\n");
#endif
#if CHOICE==BN454
    printf("BN454 Curve\n");
#endif
#if CHOICE==BN646
    printf("BN646 Curve\n");
#endif

#if CHOICE==BN254_CX
    printf("BN254_CX Curve\n");
#endif
#if CHOICE==BN254_T
    printf("BN254_T Curve\n");
#endif
#if CHOICE==BN254_T2
    printf("BN254_T2 Curve\n");
#endif
#if CHOICE==BLS455
    printf("BLS455 Curve\n");
#endif
#if CHOICE==BLS383
    printf("BLS383 Curve\n");
#endif

#if CURVETYPE==WEIERSTRASS
    printf("Weierstrass parameterization\n");
#endif
#if CURVETYPE==EDWARDS
    printf("Edwards parameterization\n");
#endif
#if CURVETYPE==MONTGOMERY
    printf("Montgomery parameterization\n");
#endif

#if CHUNK==16
    printf("16-bit Build\n");
#endif
#if CHUNK==32
    printf("32-bit Build\n");
#endif
#if CHUNK==64
    printf("64-bit Build\n");
#endif

    time((time_t *)&ran);
    pr[0]=ran;
    pr[1]=ran>>8;
    pr[2]=ran>>16;
    pr[3]=ran>>24;
    for (i=4; i<10; i++) pr[i]=i;
    RAND_seed(&RNG,10,pr);

    BIG_rcopy(x,CURVE_Gx);
#if CURVETYPE!=MONTGOMERY
    BIG_rcopy(y,CURVE_Gy);
    ECP_set(&G,x,y);
#else
    ECP_set(&G,x);
#endif

    BIG_rcopy(r,CURVE_Order);
    BIG_randomnum(s,r,&RNG);
    ECP_copy(&P,&G);
    ECP_mul(&P,r);

    if (!ECP_isinf(&P))
    {
        printf("FAILURE - rG!=O\n");
        return 0;
    }

    iterations=0;
    start=clock();
    do
    {
        ECP_copy(&P,&G);
        ECP_mul(&P,s);

        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);
    elapsed=1000.0*elapsed/iterations;
    printf("EC  mul - %8d iterations  ",iterations);
    printf(" %8.2lf ms per iteration\n",elapsed);

    printf("All tests pass\n");

    return 0;
}
