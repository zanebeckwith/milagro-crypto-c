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

package amcl

/*
#cgo CFLAGS:  -std=c99 -O3 -I. -I@CMAKE_INSTALL_PREFIX@/include -DCMAKE
#cgo LDFLAGS: -L. -L@CMAKE_INSTALL_PREFIX@/lib -lamcl_core
#include <stdio.h>
#include <stdlib.h>
#include "amcl.h"
#include "randapi.h"
#include "pbc_support.h"
#include "utils.h"
*/
import "C"
import (
	"errors"
)

/*

Today returns today's date as days elapsed from the epoch. This function uses the system clock

Args:

Returns:

    epochDate: epoch days
*/
func Today() int {
	epochDate := C.today()
	return int(epochDate)
}

/*

GetTime returns time elapsed from the epoch. This function uses the system clock

Args:

Returns:

    epochTime: epoch time

*/
func GetTime() int {
	epochTime := C.GET_TIME()
	return int(epochTime)
}

/*

HashId hashs an M-Pin Identity

Args:

    hashType: Hash function
    mpinId:   An octet pointer containing the M-Pin ID

Returns:

    hashMPinId: hash of the M-Pin ID

*/
func HashId(hashType int, mpinId []byte) (hashMPinId []byte) {
	// Form Octets
	mpinIdStr := string(mpinId)
	mpinIdOct := GetOctet(mpinIdStr)
	defer OctetFree(&mpinIdOct)
	hashMPinIdOct := GetOctetZero(hashBytes)
	defer OctetFree(&hashMPinIdOct)

	// Hash MPIN_ID
	C.HASH_ID(C.int(hashType), &mpinIdOct, &hashMPinIdOct)

	// Convert octet to bytes
	hashMPinId = OctetToBytes(&hashMPinIdOct)

	return hashMPinId
}

/*

GenerateRandomByte generates a random byte array

Args:

    RNG: Pointer to cryptographically secure pseudo-random number generator instance
    length: Gives length of random byte array

Returns:

    randomValue: Random value

*/
func GenerateRandomByte(RNG *RandNG, randomLen int) (randomValue []byte) {
	randomOct := GetOctetZero(randomLen)
	defer OctetFree(&randomOct)

	C.generateRandom(RNG.csprng(), &randomOct)

	// Convert octet to bytes
	randomValue = OctetToBytes(&randomOct)

	return randomValue[:]
}

/*

GenerateOTP returns a random six digit one time PAS_ZZZsword

Args:

    RNG: Pointer to cryptographically secure pseudo-random number generator instance

Returns:

    otp: One time PAS_ZZZsword

*/
func GenerateOTP(RNG *RandNG) int {
	OTP := C.generateOTP(RNG.csprng())
	return int(OTP)
}

/*

AesGcmEncrypt performs AES-GCM Encryption

Args:

    K: AES Key
    IV: Initialization vector
    H: header
    P: Plaintext to be encrypted

Returns:

    C: resultant ciphertext
    T: MAC
	error: in case of a bad K

*/
func AesGcmEncrypt(K, IV, H, P []byte) (C, T []byte, err error) {

	KStr := string(K)

	if len(KStr) != 16 {
		err = errors.New("Invalid Key")
		return nil, nil, err
	}

	KOct := GetOctet(KStr)
	defer OctetFree(&KOct)
	IVStr := string(IV)
	IVOct := GetOctet(IVStr)
	defer OctetFree(&IVOct)
	HStr := string(H)
	HOct := GetOctet(HStr)
	defer OctetFree(&HOct)
	PStr := string(P)
	POct := GetOctet(PStr)
	defer OctetFree(&POct)

	TOct := GetOctetZero(16)
	defer OctetFree(&TOct)
	lenC := len(PStr)
	COct := GetOctetZero(lenC)
	defer OctetFree(&COct)

	C.MPIN_AES_GCM_ENCRYPT(&KOct, &IVOct, &HOct, &POct, &COct, &TOct)

	// Convert octet to bytes
	C = OctetToBytes(&COct)
	T = OctetToBytes(&TOct)

	return C, T, nil
}

/*

AesGcmDecrypt performs AES-GCM Deryption

Args:

    K: AES Key
    IV: Initialization vector
    H: header
    C: ciphertext

Returns:

    P: resultant plaintext
    T: MAC

*/
func AesGcmDecrypt(K, IV, H, C []byte) (P, T []byte, err error) {
	KStr := string(K)

	if len(KStr) != 16 {
		err = errors.New("Invalid Key")
		return nil, nil, err
	}

	KOct := GetOctet(KStr)
	defer OctetFree(&KOct)
	IVStr := string(IV)
	IVOct := GetOctet(IVStr)
	defer OctetFree(&IVOct)
	HStr := string(H)
	HOct := GetOctet(HStr)
	defer OctetFree(&HOct)
	CStr := string(C)
	COct := GetOctet(CStr)
	defer OctetFree(&COct)

	TOct := GetOctetZero(16)
	defer OctetFree(&TOct)
	lenP := len(CStr)
	POct := GetOctetZero(lenP)
	defer OctetFree(&POct)

	C.MPIN_AES_GCM_DECRYPT(&KOct, &IVOct, &HOct, &COct, &POct, &TOct)

	// Convert octet to bytes
	P = OctetToBytes(&POct)
	T = OctetToBytes(&TOct)

	return P, T, nil
}

