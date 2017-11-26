/**
 * @file rsa_4096.go
 * @author Alessandro Budroni
 * @brief Wrappers for RSA functions
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
#cgo LDFLAGS: -lamcl_rsa_4096
#include <stdio.h>
#include <stdlib.h>
#include "amcl.h"
#include "randapi.h"
#include "rsa_4096.h"
#include "utils.h"
*/
import "C"

// RSA Constant
const RFS_4096 int = int(C.RFS_4096)     // RFS_4096 is the RSA Public Key Size in bytes
const FFLEN_4096 int = int(C.FFLEN_4096) // FFLEN_4096 consists in 2^n multiplier of BIGBITS to specify supported Finite Field size, e.g 2048=256*2^3 where BIGBITS=256

const HASH_TYPE_RSA_4096 int = int(C.HASH_TYPE_RSA_4096) // HASH_TYPE_RSA_4096 is the chosen Hash algorithm

// RSAKeyPair generates an RSA key pair
func RSAKeyPair_4096(RNG *RandNG, e int32, P []byte, Q []byte) (RSAPrivateKey, RSAPublicKey) {
	PStr := string(P)
	POct := GetOctet(PStr)
	defer OctetFree(&POct)
	QStr := string(Q)
	QOct := GetOctet(QStr)
	defer OctetFree(&QOct)
	eVal := C.int32_t(e)
	var RSA_PubKey C.rsa_public_key_4096
	var RSA_PrivKey C.rsa_private_key_4096

	C.RSA_4096_KEY_PAIR(RNG.csprng(), eVal, &RSA_PrivKey, &RSA_PubKey, &POct, &QOct)
	return &RSA_PrivKey, &RSA_PubKey
}

// RSAEncrypt_4096 encrypts F with the public key
func RSAEncrypt_4096(publicKey RSAPublicKey, F []byte) (G []byte) {
	FStr := string(F)
	FOct := GetOctet(FStr)
	defer OctetFree(&FOct)
	GOct := GetOctetZero(RFS_4096)
	defer OctetFree(&GOct)

	RSA_PubKey := publicKey.(*C.rsa_public_key_4096)
	C.RSA_4096_ENCRYPT(RSA_PubKey, &FOct, &GOct)
	G = OctetToBytes(&GOct)
	return G[:]
}

// RSADecrypt_4096 decrypts G with the private key
func RSADecrypt_4096(privateKey RSAPrivateKey, G []byte) (F []byte) {
	GStr := string(G)
	GOct := GetOctet(GStr)
	defer OctetFree(&GOct)
	FOct := GetOctetZero(RFS_4096)
	defer OctetFree(&FOct)

	RSA_PrivKey := privateKey.(*C.rsa_private_key_4096)
	C.RSA_4096_DECRYPT(RSA_PrivKey, &GOct, &FOct)
	F = OctetToBytes(&FOct)
	return F[:]
}

// RSAPrivateKeyKill_4096 destroys an RSA private Key
func RSAPrivateKeyKill_4096(privateKey RSAPrivateKey) {
	RSA_PrivKey := privateKey.(*C.rsa_private_key_4096)
	C.RSA_4096_PRIVATE_KEY_KILL(RSA_PrivKey)
}
