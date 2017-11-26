/**
 * @file ecdsa_GOLDILOCKS.go
 * @author Alessandro Budroni
 * @brief Wrappers for ECDSA functions
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

package amcl

/*
#cgo LDFLAGS: -lamcl_curve_GOLDILOCKS
#include <stdio.h>
#include <stdlib.h>
#include "amcl.h"
#include "ecdh_GOLDILOCKS.h"
*/
import "C"

const EFS_GOLDILOCKS int = int(C.EFS_GOLDILOCKS) // EFS is the ECC Field Size in bytes
const EGS_GOLDILOCKS int = int(C.EGS_GOLDILOCKS) // EGS is the ECC Group Size in bytes

// ECPKeyPairGenerate_GOLDILOCKS generates an ECC public/private key pair, S is provided as input if RNG is null
func ECPKeyPairGenerate_GOLDILOCKS(RNG *RandNG, S []byte) (int, []byte, []byte) {
	WOct := GetOctetZero(2*EFS_GOLDILOCKS + 1)
	defer OctetFree(&WOct)
	var SOct C.octet
	var rtn C.int
	if RNG == nil {
		SStr := string(S)
		SOct = GetOctet(SStr)
		defer OctetFree(&SOct)
		rtn = C.ECP_GOLDILOCKS_KEY_PAIR_GENERATE(nil, &SOct, &WOct)
	} else {
		SOct = GetOctetZero(EGS_GOLDILOCKS)
		defer OctetFree(&SOct)
		rtn = C.ECP_GOLDILOCKS_KEY_PAIR_GENERATE(RNG.csprng(), &SOct, &WOct)
	}
	errorCode := int(rtn)
	W := OctetToBytes(&WOct)
	S = OctetToBytes(&SOct)
	return errorCode, S[:], W[:]
}

// ECPPublicKeyValidate_GOLDILOCKS validates an ECC public key, if = 0 just does some simple checks, else tests that W is of the correct order, return 0 if ok, error code otherwise
func ECPPublicKeyValidate_GOLDILOCKS(f int, W []byte) int {
	WStr := string(W)
	WOct := GetOctet(WStr)
	defer OctetFree(&WOct)
	rtn := C.ECP_GOLDILOCKS_PUBLIC_KEY_VALIDATE(&WOct)
	return int(rtn)
}

// ECPSpDsa_GOLDILOCKS signs with ECDSA Signature a message M - K is used when RNG is null
func ECPSpDsa_GOLDILOCKS(hashType int, RNG *RandNG, K []byte, S []byte, M []byte) (errorCode int, C []byte, D []byte) {
	KStr := string(K)
	KOct := GetOctet(KStr)
	defer OctetFree(&KOct)
	SStr := string(S)
	SOct := GetOctet(SStr)
	defer OctetFree(&SOct)
	MStr := string(M)
	MOct := GetOctet(MStr)
	defer OctetFree(&MOct)
	COct := GetOctetZero(EGS_GOLDILOCKS)
	defer OctetFree(&COct)
	DOct := GetOctetZero(EGS_GOLDILOCKS)
	defer OctetFree(&DOct)

	rtn := C.ECP_GOLDILOCKS_SP_DSA(C.int(hashType), RNG.csprng(), &KOct, &SOct, &MOct, &COct, &DOct)
	errorCode = int(rtn)
	C = OctetToBytes(&COct)
	D = OctetToBytes(&DOct)
	return errorCode, C[:], D[:]
}

// ECPVpDsa_GOLDILOCKS verifies an ECDSA Signature on message M
func ECPVpDsa_GOLDILOCKS(hashType int, W []byte, M []byte, C []byte, D []byte) (errorCode int) {
	WStr := string(W)
	WOct := GetOctet(WStr)
	defer OctetFree(&WOct)
	MStr := string(M)
	MOct := GetOctet(MStr)
	defer OctetFree(&MOct)
	CStr := string(C)
	COct := GetOctet(CStr)
	defer OctetFree(&COct)
	DStr := string(D)
	DOct := GetOctet(DStr)
	defer OctetFree(&DOct)

	rtn := C.ECP_GOLDILOCKS_VP_DSA(C.int(hashType), &WOct, &MOct, &COct, &DOct)
	errorCode = int(rtn)
	return errorCode
}
