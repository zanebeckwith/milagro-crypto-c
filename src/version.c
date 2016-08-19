/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

#include "version.h"

/*! \brief Print version number and information about the build
 *
 *  Print version number and information about the build
 *
 */
void amcl_version(void)
{
    printf("AMCL Version: %d.%d.%d\n", AMCL_VERSION_MAJOR, AMCL_VERSION_MINOR, AMCL_VERSION_PATCH);

    printf("OS: %s\n", OS);

    printf("CHUNK: %d\n", CHUNK);

    /* Curve types */
#if CURVETYPE==WEIERSTRASS
    printf("CURVETYPE: WEIERSTRASS\n");
#endif

#if CURVETYPE==EDWARDS
    printf("CURVETYPE: EDWARDS\n");
#endif

#if CURVETYPE==MONTGOMERY
    printf("CURVETYPE: MONTGOMERY\n");
#endif

    /* curves */
#if CHOICE==BN254
    printf("CHOICE: BN254\n");
#endif

#if CHOICE==BN254_T
    printf("CHOICE: BN254_T\n");
#endif

#if CHOICE==BN254_T2
    printf("CHOICE: BN254_T2\n");
#endif

#if CHOICE==BN254_CX
    printf("CHOICE: BN254_CX\n");
#endif

#if CHOICE==NIST256
    printf("CHOICE: NIST256\n");
#endif

#if CHOICE==MF254
    printf("CHOICE: MF254\n");
#endif

#if CHOICE==MF256
    printf("CHOICE: MF256\n");
#endif

#if CHOICE==MS255
    printf("CHOICE: MS255\n");
#endif

#if CHOICE==MS256
    printf("CHOICE: MS256\n");
#endif

#if CHOICE==C25519
    printf("CHOICE: C25519\n");
#endif

#if CHOICE==BRAINPOOL
    printf("CHOICE: BRAINPOOL\n");
#endif

#if CHOICE==ANSSI
    printf("CHOICE: ANSSI\n");
#endif

#if CHOICE==HIFIVE
    printf("CHOICE: HIFIVE\n");
#endif

#if CHOICE==GOLDILOCKS
    printf("CHOICE: GOLDILOCKS\n");
#endif

#if CHOICE==NIST384
    printf("CHOICE: NIST384\n");
#endif

#if CHOICE==C41417
    printf("CHOICE: C41417\n");
#endif

#if CHOICE==NIST521
    printf("CHOICE: NIST521\n");
#endif

#if CHOICE==BN646
    printf("CHOICE: BN646\n");
#endif

#if CHOICE==BN454
    printf("CHOICE: BN454\n");
#endif

#if CHOICE==BLS455
    printf("CHOICE: BLS455\n");
#endif

    printf("FFLEN: %d\n", FFLEN);

    /* modulus types */
#if MODTYPE==NOT_SPECIAL
    printf("MODTYPE: Modulus of no exploitable form\n");
#endif

#if MODTYPE==PSEUDO_MERSENNE
    printf("MODTYPE: Pseudo-mersenne modulus of form $2^n-c$\n");
#endif

#if MODTYPE==MONTGOMERY_FRIENDLY
    printf("MODTYPE: Montgomery Friendly modulus of form $2^a(2^b-c)-1$\n");
#endif

#if MODTYPE==GENERALISED_MERSENNE
    printf("MODTYPE: Generalised-mersenne modulus of form $2^n-2^m-1$\n");
#endif

    printf("MBITS - Number of bits in Modulus: %d\n", MBITS);
    printf("MODBYTES - Number of bytes in Modulus: %d\n", MODBYTES);
    printf("BASEBITS - Numbers represented to base 2*BASEBITS: %d\n", BASEBITS);
    printf("NLEN - Number of words in BIG: %d\n", NLEN);

    BIG p, r;
    BIG_rcopy(p,Modulus);
    printf("Modulus p = ");
    BIG_output(p);
    printf("\n");
    BIG_rcopy(r,CURVE_Order);
    printf("CURVE_Order r = ");
    BIG_output(r);
    printf("\n");
}
