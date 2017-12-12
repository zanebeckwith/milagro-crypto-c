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

// #include "rsa_3072.h"
// #include "rsa_support.h"
import "C"

// RSA_3072_DECRYPT is a go wrapper for C.RSA_3072_DECRYPT
func RSA_3072_DECRYPT(priv RSAPrivateKey, G *Octet, F *Octet) {
	C.RSA_3072_DECRYPT(priv.(*C.rsa_private_key_3072), (*C.octet)(G), (*C.octet)(F))
}

// RSA_3072_ENCRYPT is a go wrapper for C.RSA_3072_ENCRYPT
func RSA_3072_ENCRYPT(pub RSAPublicKey, F *Octet, G *Octet) {
	C.RSA_3072_ENCRYPT(pub.(*C.rsa_public_key_3072), (*C.octet)(F), (*C.octet)(G))
}

// RSA_3072_KEY_PAIR is a go wrapper for C.RSA_3072_KEY_PAIR
func RSA_3072_KEY_PAIR(rng *Rand, e int32, priv RSAPrivateKey, pub RSAPublicKey, p *Octet, q *Octet) {
	C.RSA_3072_KEY_PAIR((*C.csprng)(rng), C.sign32(e), priv.(*C.rsa_private_key_3072), pub.(*C.rsa_public_key_3072), (*C.octet)(p), (*C.octet)(q))
}

// RSA_3072_PRIVATE_KEY_KILL is a go wrapper for C.RSA_3072_PRIVATE_KEY_KILL
func RSA_3072_PRIVATE_KEY_KILL(PRIV RSAPrivateKey) {
	C.RSA_3072_PRIVATE_KEY_KILL(PRIV.(*C.rsa_private_key_3072))
}
