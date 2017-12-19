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

// Generated by gen/wrappers/main.go from wrap/wrappers.go.tmpl.

package wrap

// #cgo LDFLAGS: -lamcl_rsa_2048
// #include "rsa_2048.h"
// #include "rsa_support.h"
import "C"

const (
	RFS_2048               = int(C.RFS_2048)           // RFS_2048 is the RSA Public Key Size in bytes
	FFLEN_2048             = int(C.FFLEN_2048)         // FFLEN_2048 consists in 2^n multiplier of BIGBITS to specify supported Finite Field size, e.g 2048=256*2^3 where BIGBITS=256
	HASH_TYPE_RSA_2048 int = int(C.HASH_TYPE_RSA_2048) // HASH_TYPE_RSA_2048 is the chosen Hash algorithm
)

func NewRSAPrivateKey_2048() RSAPrivateKey {
	return &C.rsa_private_key_2048{}
}

func NewRSAPublicKey_2048() RSAPublicKey {
	return &C.rsa_public_key_2048{}
}

// RSA_2048_DECRYPT is a go wrapper for C.RSA_2048_DECRYPT
func RSA_2048_DECRYPT(priv RSAPrivateKey, G *Octet, F *Octet) {
	C.RSA_2048_DECRYPT(priv.(*C.rsa_private_key_2048), (*C.octet)(G), (*C.octet)(F))
}

// RSA_2048_ENCRYPT is a go wrapper for C.RSA_2048_ENCRYPT
func RSA_2048_ENCRYPT(pub RSAPublicKey, F *Octet, G *Octet) {
	C.RSA_2048_ENCRYPT(pub.(*C.rsa_public_key_2048), (*C.octet)(F), (*C.octet)(G))
}

// RSA_2048_KEY_PAIR is a go wrapper for C.RSA_2048_KEY_PAIR
func RSA_2048_KEY_PAIR(rng *Rand, e int32, priv RSAPrivateKey, pub RSAPublicKey, p *Octet, q *Octet) {
	C.RSA_2048_KEY_PAIR((*C.csprng)(rng), C.sign32(e), priv.(*C.rsa_private_key_2048), pub.(*C.rsa_public_key_2048), (*C.octet)(p), (*C.octet)(q))
}

// RSA_2048_PRIVATE_KEY_KILL is a go wrapper for C.RSA_2048_PRIVATE_KEY_KILL
func RSA_2048_PRIVATE_KEY_KILL(PRIV RSAPrivateKey) {
	C.RSA_2048_PRIVATE_KEY_KILL(PRIV.(*C.rsa_private_key_2048))
}
