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

/**
 * @file wcc.h
 * @author Mike Scott and Kealan McCusker
 * @date 28th April 2016
 * @brief Wang / Chow Choo (WCC)  header file
 *
 * defines structures
 * declares functions
 *
 */

#ifndef WCC_H
#define WCC_H

#include "amcl.h"

/* Field size is assumed to be greater than or equal to group size */

#define PGS MODBYTES  /**< MPIN Group Size */
#define PFS MODBYTES  /**< MPIN Field Size */
#define PAS 16  /**< MPIN Symmetric Key Size */

#define WCC_OK                     0    /**< Function completed without error */
#define WCC_INVALID_POINT         -51	/**< Point is NOT on the curve */

#define TIME_SLOT_MINUTES 1440 /**< Time Slot = 1 day */
#define HASH_BYTES MODBYTES

#define HASH_TYPE_WCC SHA256 /**< Choose Hash function */

/*! \brief Generate a random integer */
int WCC_RANDOM_GENERATE(csprng *RNG,octet* S);

/*! \brief Hash EC Points and Id to an integer */
void WCC_Hq(int sha, octet *A,octet *B,octet *C,octet *D,octet *h);

/*! \brief Calculate value in G2 multiplied by an integer */
int WCC_GET_G2_MULTIPLE(int sha, int hashDone,octet *S,octet *ID,octet *VG2);

/*! \brief Calculate value in G1 multiplied by an integer */
int WCC_GET_G1_MULTIPLE(int sha, int hashDone,octet *S,octet *ID,octet *VG1);

/*! \brief Calculate a value in G1 used for when time permits are enabled */
int WCC_GET_G1_TPMULT(int sha, int date, octet *S,octet *ID,octet *VG1);

/*! \brief Calculate a value in G2 used for when time permits are enabled */
int WCC_GET_G2_TPMULT(int sha, int date, octet *S,octet *ID,octet *VG2);

/*! \brief Calculate time permit in G2 */
int WCC_GET_G1_PERMIT(int sha, int date,octet *S,octet *HID,octet *G1TP);

/*! \brief Calculate time permit in G2 */
int WCC_GET_G2_PERMIT(int sha, int date,octet *S,octet *HID,octet *G2TP);

/*! \brief Calculate the sender AES key */
int WCC_SENDER_KEY(int sha, int date, octet *xOct, octet *piaOct, octet *pibOct, octet *PbG2Oct, octet *PgG1Oct, octet *AKeyG1Oct, octet *ATPG1Oct, octet *IdBOct, octet *AESKeyOct);

/*! \brief Calculate the receiver AES key */
int WCC_RECEIVER_KEY(int sha, int date, octet *yOct, octet *wOct,  octet *piaOct, octet *pibOct,  octet *PaG1Oct, octet *PgG1Oct, octet *BKeyG2Oct,octet *BTPG2Oct,  octet *IdAOct, octet *AESKeyOct);

/*! \brief Encrypt data using AES GCM */
void WCC_AES_GCM_ENCRYPT(octet *K,octet *IV,octet *H,octet *P,octet *C,octet *T);

/*! \brief Decrypt data using AES GCM */
void WCC_AES_GCM_DECRYPT(octet *K,octet *IV,octet *H,octet *C,octet *P,octet *T);

/*!  \brief Perform sha256 */
void WCC_HASH_ID(int sha, octet *,octet *);

/*! \brief Add two members from the group G1 */
int WCC_RECOMBINE_G1(octet *,octet *,octet *);

/*! \brief Add two members from the group G2 */
int WCC_RECOMBINE_G2(octet *,octet *,octet *);

/*! \brief Get today's date as days from the epoch */
unsign32 WCC_today(void);

/*! \brief Initialise a random number generator */
void WCC_CREATE_CSPRNG(csprng *,octet *);

/*! \brief Kill a random number generator */
void WCC_KILL_CSPRNG(csprng *RNG);


#endif
