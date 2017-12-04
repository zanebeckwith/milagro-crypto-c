// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package amcl

/*
#cgo LDFLAGS: -lamcl_rsa_3072
#include <stdio.h>
#include <stdlib.h>
#include "amcl.h"
#include "randapi.h"
#include "rsa_3072.h"
#include "utils.h"
#include "wrappers_generated.h"
*/
import "C"

// RSA Constant
const RFS_3072 int = int(C.RFS_3072)     // RFS_3072 is the RSA Public Key Size in bytes
const FFLEN_3072 int = int(C.FFLEN_3072) // FFLEN_3072 consists in 2^n multiplier of BIGBITS to specify supported Finite Field size, e.g 2048=256*2^3 where BIGBITS=256

const HASH_TYPE_RSA_3072 int = int(C.HASH_TYPE_RSA_3072) // HASH_TYPE_RSA_3072 is the chosen Hash algorithm

// RSAKeyPair generates an RSA key pair
func RSAKeyPair_3072(rng *Rand, e int32, p []byte, q []byte) (RSAPrivateKey, RSAPublicKey) {
	var prvKey C.rsa_private_key_3072
	var pubKey C.rsa_public_key_3072

	C._RSA_3072_KEY_PAIR(rng.csprng(), C.int32_t(e), &prvKey, &pubKey, *newOctet(p), *newOctet(q))
	return &prvKey, &pubKey

}

// RSAEncrypt_3072 encrypts F with the public key
func RSAEncrypt_3072(pubKey RSAPublicKey, f []byte) []byte {
	g := make([]byte, RFS_3072)
	C._RSA_3072_ENCRYPT(pubKey.(*C.rsa_public_key_3072), *newOctet(f), *makeOctet(g))
	return g
}

// RSADecrypt_3072 decrypts G with the private key
func RSADecrypt_3072(prvKey RSAPrivateKey, g []byte) []byte {
	f := make([]byte, RFS_3072)
	C._RSA_3072_DECRYPT(prvKey.(*C.rsa_private_key_3072), *newOctet(g), *makeOctet(f))
	return f
}

// RSAPrivateKeyKill_3072 destroys an RSA private Key
func RSAPrivateKeyKill_3072(prvKey RSAPrivateKey) {
	C._RSA_3072_PRIVATE_KEY_KILL(prvKey.(*C.rsa_private_key_3072))
}
