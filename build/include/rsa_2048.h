/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License") you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

/**
 * @file rsa.h
 * @author Mike Scott and Kealan McCusker
 * @date 2nd June 2015
 * @brief RSA Header file for implementation of RSA protocol
 *
 * declares functions
 *
 */

#ifndef RSA_2048_H
#define RSA_2048_H

#include "ff_2048.h"
#include "rsa_support.h"

/*** START OF USER CONFIGURABLE SECTION -  ***/

#define HASH_TYPE_RSA_2048 SHA256 /**< Chosen Hash algorithm */

/*** END OF USER CONFIGURABLE SECTION ***/

#define RFS_2048 MODBYTES_1024_58*FFLEN_2048 /**< RSA Public Key Size in bytes */


/**
	@brief Integer Factorisation Public Key
*/

typedef struct
{
    sign32 e     /**< RSA exponent (typically 65537) */
    BIG_1024_58 n[FFLEN_2048] /**< An array of BIGs to store public key */
} rsa_public_key_2048

/**
	@brief Integer Factorisation Private Key
*/

typedef struct
{
    BIG_1024_58 p[FFLEN_2048/2]  /**< secret prime p  */
    BIG_1024_58 q[FFLEN_2048/2]  /**< secret prime q  */
    BIG_1024_58 dp[FFLEN_2048/2] /**< decrypting exponent mod (p-1)  */
    BIG_1024_58 dq[FFLEN_2048/2] /**< decrypting exponent mod (q-1)  */
    BIG_1024_58 c[FFLEN_2048/2]  /**< 1/p mod q */
} rsa_private_key_2048

/* RSA Auxiliary Functions */

extern void RSA_2048_KEY_PAIR(csprng *R,sign32 e,rsa_private_key_2048* PRIV,rsa_public_key_2048* PUB,octet *P, octet* Q)

/**	@brief RSA encryption of suitably padded plaintext
 *
	@param PUB the input RSA public key
	@param F is input padded message
	@param G is the output ciphertext
 */
extern void RSA_2048_ENCRYPT(rsa_public_key_2048* PUB,octet *F,octet *G)
/**	@brief RSA decryption of ciphertext
 *
	@param PRIV the input RSA private key
	@param G is the input ciphertext
	@param F is output plaintext (requires unpadding)

 */
extern void RSA_2048_DECRYPT(rsa_private_key_2048* PRIV,octet *G,octet *F)
/**	@brief Destroy an RSA private Key
 *
	@param PRIV the input RSA private key. Destroyed on output.
 */
extern void RSA_2048_PRIVATE_KEY_KILL(rsa_private_key_2048 *PRIV)
/**	@brief Populates an RSA public key from an octet string
 *
	Creates RSA public key from big-endian base 256 form.
	@param x FF instance to be created from an octet string
	@param S input octet string
 */
extern void RSA_2048_fromOctet(BIG_1024_58 *x,octet *S)



#endif
