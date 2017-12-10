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

// #cgo CFLAGS: -std=c99 -O3 -I.
// #cgo LDFLAGS: -L. -lamcl_core
// #include "amcl.h"
// #include "mpin_BLS383.h"
// #include "mpin_BN254.h"
// #include "mpin_BN254CX.h"
// #include "randapi.h"
// #include "rsa_2048.h"
// #include "rsa_3072.h"
// #include "rsa_4096.h"
// #include "rsa_support.h"
// #include "utils.h"
import "C"

// PKCS15 is a go wrapper for C.PKCS15
func PKCS15(h int, m *Octet, w *Octet) error {
	code := C.PKCS15(C.int(h), (*C.octet)(m), (*C.octet)(w))
	return newError(int(code))
}

// OAEP_ENCODE is a go wrapper for C.OAEP_ENCODE
func OAEP_ENCODE(h int, m *Octet, rng *Rand, p *Octet, f *Octet) error {
	code := C.OAEP_ENCODE(C.int(h), (*C.octet)(m), (*C.csprng)(rng), (*C.octet)(p), (*C.octet)(f))
	return newError(int(code))
}

// OAEP_DECODE is a go wrapper for C.OAEP_DECODE
func OAEP_DECODE(h int, p *Octet, f *Octet) error {
	code := C.OAEP_DECODE(C.int(h), (*C.octet)(p), (*C.octet)(f))
	return newError(int(code))
}

// CREATE_CSPRNG is a go wrapper for C.CREATE_CSPRNG
func CREATE_CSPRNG(R *Rand, S *Octet) {
	C.CREATE_CSPRNG((*C.csprng)(R), (*C.octet)(S))
}

// RSA_2048_DECRYPT is a go wrapper for C.RSA_2048_DECRYPT
func RSA_2048_DECRYPT(priv RSAPrivateKey, G *Octet, F *Octet) {
	C.RSA_2048_DECRYPT(priv.(*C.rsa_private_key_2048), (*C.octet)(G), (*C.octet)(F))
}

// RSA_3072_DECRYPT is a go wrapper for C.RSA_3072_DECRYPT
func RSA_3072_DECRYPT(priv RSAPrivateKey, G *Octet, F *Octet) {
	C.RSA_3072_DECRYPT(priv.(*C.rsa_private_key_3072), (*C.octet)(G), (*C.octet)(F))
}

// RSA_4096_DECRYPT is a go wrapper for C.RSA_4096_DECRYPT
func RSA_4096_DECRYPT(priv RSAPrivateKey, G *Octet, F *Octet) {
	C.RSA_4096_DECRYPT(priv.(*C.rsa_private_key_4096), (*C.octet)(G), (*C.octet)(F))
}

// RSA_2048_ENCRYPT is a go wrapper for C.RSA_2048_ENCRYPT
func RSA_2048_ENCRYPT(pub RSAPublicKey, F *Octet, G *Octet) {
	C.RSA_2048_ENCRYPT(pub.(*C.rsa_public_key_2048), (*C.octet)(F), (*C.octet)(G))
}

// RSA_3072_ENCRYPT is a go wrapper for C.RSA_3072_ENCRYPT
func RSA_3072_ENCRYPT(pub RSAPublicKey, F *Octet, G *Octet) {
	C.RSA_3072_ENCRYPT(pub.(*C.rsa_public_key_3072), (*C.octet)(F), (*C.octet)(G))
}

// RSA_4096_ENCRYPT is a go wrapper for C.RSA_4096_ENCRYPT
func RSA_4096_ENCRYPT(pub RSAPublicKey, F *Octet, G *Octet) {
	C.RSA_4096_ENCRYPT(pub.(*C.rsa_public_key_4096), (*C.octet)(F), (*C.octet)(G))
}

// RSA_2048_KEY_PAIR is a go wrapper for C.RSA_2048_KEY_PAIR
func RSA_2048_KEY_PAIR(rng *Rand, e int32, priv RSAPrivateKey, pub RSAPublicKey, p *Octet, q *Octet) {
	C.RSA_2048_KEY_PAIR((*C.csprng)(rng), C.sign32(e), priv.(*C.rsa_private_key_2048), pub.(*C.rsa_public_key_2048), (*C.octet)(p), (*C.octet)(q))
}

// RSA_3072_KEY_PAIR is a go wrapper for C.RSA_3072_KEY_PAIR
func RSA_3072_KEY_PAIR(rng *Rand, e int32, priv RSAPrivateKey, pub RSAPublicKey, p *Octet, q *Octet) {
	C.RSA_3072_KEY_PAIR((*C.csprng)(rng), C.sign32(e), priv.(*C.rsa_private_key_3072), pub.(*C.rsa_public_key_3072), (*C.octet)(p), (*C.octet)(q))
}

// RSA_4096_KEY_PAIR is a go wrapper for C.RSA_4096_KEY_PAIR
func RSA_4096_KEY_PAIR(rng *Rand, e int32, priv RSAPrivateKey, pub RSAPublicKey, p *Octet, q *Octet) {
	C.RSA_4096_KEY_PAIR((*C.csprng)(rng), C.sign32(e), priv.(*C.rsa_private_key_4096), pub.(*C.rsa_public_key_4096), (*C.octet)(p), (*C.octet)(q))
}

// RSA_2048_PRIVATE_KEY_KILL is a go wrapper for C.RSA_2048_PRIVATE_KEY_KILL
func RSA_2048_PRIVATE_KEY_KILL(PRIV RSAPrivateKey) {
	C.RSA_2048_PRIVATE_KEY_KILL(PRIV.(*C.rsa_private_key_2048))
}

// RSA_3072_PRIVATE_KEY_KILL is a go wrapper for C.RSA_3072_PRIVATE_KEY_KILL
func RSA_3072_PRIVATE_KEY_KILL(PRIV RSAPrivateKey) {
	C.RSA_3072_PRIVATE_KEY_KILL(PRIV.(*C.rsa_private_key_3072))
}

// RSA_4096_PRIVATE_KEY_KILL is a go wrapper for C.RSA_4096_PRIVATE_KEY_KILL
func RSA_4096_PRIVATE_KEY_KILL(PRIV RSAPrivateKey) {
	C.RSA_4096_PRIVATE_KEY_KILL(PRIV.(*C.rsa_private_key_4096))
}

// MPIN_BLS383_CLIENT_1 is a go wrapper for C.MPIN_BLS383_CLIENT_1
func MPIN_BLS383_CLIENT_1(h int, d int, ID *Octet, R *Rand, x *Octet, pin int, T *Octet, S *Octet, U *Octet, UT *Octet, TP *Octet) error {
	code := C.MPIN_BLS383_CLIENT_1(C.int(h), C.int(d), (*C.octet)(ID), (*C.csprng)(R), (*C.octet)(x), C.int(pin), (*C.octet)(T), (*C.octet)(S), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(TP))
	return newError(int(code))
}

// MPIN_BN254_CLIENT_1 is a go wrapper for C.MPIN_BN254_CLIENT_1
func MPIN_BN254_CLIENT_1(h int, d int, ID *Octet, R *Rand, x *Octet, pin int, T *Octet, S *Octet, U *Octet, UT *Octet, TP *Octet) error {
	code := C.MPIN_BN254_CLIENT_1(C.int(h), C.int(d), (*C.octet)(ID), (*C.csprng)(R), (*C.octet)(x), C.int(pin), (*C.octet)(T), (*C.octet)(S), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(TP))
	return newError(int(code))
}

// MPIN_BN254CX_CLIENT_1 is a go wrapper for C.MPIN_BN254CX_CLIENT_1
func MPIN_BN254CX_CLIENT_1(h int, d int, ID *Octet, R *Rand, x *Octet, pin int, T *Octet, S *Octet, U *Octet, UT *Octet, TP *Octet) error {
	code := C.MPIN_BN254CX_CLIENT_1(C.int(h), C.int(d), (*C.octet)(ID), (*C.csprng)(R), (*C.octet)(x), C.int(pin), (*C.octet)(T), (*C.octet)(S), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(TP))
	return newError(int(code))
}

// MPIN_BLS383_CLIENT_2 is a go wrapper for C.MPIN_BLS383_CLIENT_2
func MPIN_BLS383_CLIENT_2(x *Octet, y *Octet, V *Octet) error {
	code := C.MPIN_BLS383_CLIENT_2((*C.octet)(x), (*C.octet)(y), (*C.octet)(V))
	return newError(int(code))
}

// MPIN_BN254_CLIENT_2 is a go wrapper for C.MPIN_BN254_CLIENT_2
func MPIN_BN254_CLIENT_2(x *Octet, y *Octet, V *Octet) error {
	code := C.MPIN_BN254_CLIENT_2((*C.octet)(x), (*C.octet)(y), (*C.octet)(V))
	return newError(int(code))
}

// MPIN_BN254CX_CLIENT_2 is a go wrapper for C.MPIN_BN254CX_CLIENT_2
func MPIN_BN254CX_CLIENT_2(x *Octet, y *Octet, V *Octet) error {
	code := C.MPIN_BN254CX_CLIENT_2((*C.octet)(x), (*C.octet)(y), (*C.octet)(V))
	return newError(int(code))
}

// MPIN_BLS383_CLIENT_KEY is a go wrapper for C.MPIN_BLS383_CLIENT_KEY
func MPIN_BLS383_CLIENT_KEY(h int, g1 *Octet, g2 *Octet, pin int, r *Octet, x *Octet, p *Octet, T *Octet, K *Octet) error {
	code := C.MPIN_BLS383_CLIENT_KEY(C.int(h), (*C.octet)(g1), (*C.octet)(g2), C.int(pin), (*C.octet)(r), (*C.octet)(x), (*C.octet)(p), (*C.octet)(T), (*C.octet)(K))
	return newError(int(code))
}

// MPIN_BN254_CLIENT_KEY is a go wrapper for C.MPIN_BN254_CLIENT_KEY
func MPIN_BN254_CLIENT_KEY(h int, g1 *Octet, g2 *Octet, pin int, r *Octet, x *Octet, p *Octet, T *Octet, K *Octet) error {
	code := C.MPIN_BN254_CLIENT_KEY(C.int(h), (*C.octet)(g1), (*C.octet)(g2), C.int(pin), (*C.octet)(r), (*C.octet)(x), (*C.octet)(p), (*C.octet)(T), (*C.octet)(K))
	return newError(int(code))
}

// MPIN_BN254CX_CLIENT_KEY is a go wrapper for C.MPIN_BN254CX_CLIENT_KEY
func MPIN_BN254CX_CLIENT_KEY(h int, g1 *Octet, g2 *Octet, pin int, r *Octet, x *Octet, p *Octet, T *Octet, K *Octet) error {
	code := C.MPIN_BN254CX_CLIENT_KEY(C.int(h), (*C.octet)(g1), (*C.octet)(g2), C.int(pin), (*C.octet)(r), (*C.octet)(x), (*C.octet)(p), (*C.octet)(T), (*C.octet)(K))
	return newError(int(code))
}

// MPIN_BLS383_CLIENT is a go wrapper for C.MPIN_BLS383_CLIENT
func MPIN_BLS383_CLIENT(h int, d int, ID *Octet, R *Rand, x *Octet, pin int, T *Octet, V *Octet, U *Octet, UT *Octet, TP *Octet, MESSAGE *Octet, t int, y *Octet) error {
	code := C.MPIN_BLS383_CLIENT(C.int(h), C.int(d), (*C.octet)(ID), (*C.csprng)(R), (*C.octet)(x), C.int(pin), (*C.octet)(T), (*C.octet)(V), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(TP), (*C.octet)(MESSAGE), C.int(t), (*C.octet)(y))
	return newError(int(code))
}

// MPIN_BN254_CLIENT is a go wrapper for C.MPIN_BN254_CLIENT
func MPIN_BN254_CLIENT(h int, d int, ID *Octet, R *Rand, x *Octet, pin int, T *Octet, V *Octet, U *Octet, UT *Octet, TP *Octet, MESSAGE *Octet, t int, y *Octet) error {
	code := C.MPIN_BN254_CLIENT(C.int(h), C.int(d), (*C.octet)(ID), (*C.csprng)(R), (*C.octet)(x), C.int(pin), (*C.octet)(T), (*C.octet)(V), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(TP), (*C.octet)(MESSAGE), C.int(t), (*C.octet)(y))
	return newError(int(code))
}

// MPIN_BN254CX_CLIENT is a go wrapper for C.MPIN_BN254CX_CLIENT
func MPIN_BN254CX_CLIENT(h int, d int, ID *Octet, R *Rand, x *Octet, pin int, T *Octet, V *Octet, U *Octet, UT *Octet, TP *Octet, MESSAGE *Octet, t int, y *Octet) error {
	code := C.MPIN_BN254CX_CLIENT(C.int(h), C.int(d), (*C.octet)(ID), (*C.csprng)(R), (*C.octet)(x), C.int(pin), (*C.octet)(T), (*C.octet)(V), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(TP), (*C.octet)(MESSAGE), C.int(t), (*C.octet)(y))
	return newError(int(code))
}

// MPIN_BLS383_EXTRACT_PIN is a go wrapper for C.MPIN_BLS383_EXTRACT_PIN
func MPIN_BLS383_EXTRACT_PIN(h int, ID *Octet, pin int, CS *Octet) error {
	code := C.MPIN_BLS383_EXTRACT_PIN(C.int(h), (*C.octet)(ID), C.int(pin), (*C.octet)(CS))
	return newError(int(code))
}

// MPIN_BN254_EXTRACT_PIN is a go wrapper for C.MPIN_BN254_EXTRACT_PIN
func MPIN_BN254_EXTRACT_PIN(h int, ID *Octet, pin int, CS *Octet) error {
	code := C.MPIN_BN254_EXTRACT_PIN(C.int(h), (*C.octet)(ID), C.int(pin), (*C.octet)(CS))
	return newError(int(code))
}

// MPIN_BN254CX_EXTRACT_PIN is a go wrapper for C.MPIN_BN254CX_EXTRACT_PIN
func MPIN_BN254CX_EXTRACT_PIN(h int, ID *Octet, pin int, CS *Octet) error {
	code := C.MPIN_BN254CX_EXTRACT_PIN(C.int(h), (*C.octet)(ID), C.int(pin), (*C.octet)(CS))
	return newError(int(code))
}

// MPIN_BLS383_GET_CLIENT_PERMIT is a go wrapper for C.MPIN_BLS383_GET_CLIENT_PERMIT
func MPIN_BLS383_GET_CLIENT_PERMIT(h int, d int, S *Octet, ID *Octet, TP *Octet) error {
	code := C.MPIN_BLS383_GET_CLIENT_PERMIT(C.int(h), C.int(d), (*C.octet)(S), (*C.octet)(ID), (*C.octet)(TP))
	return newError(int(code))
}

// MPIN_BN254_GET_CLIENT_PERMIT is a go wrapper for C.MPIN_BN254_GET_CLIENT_PERMIT
func MPIN_BN254_GET_CLIENT_PERMIT(h int, d int, S *Octet, ID *Octet, TP *Octet) error {
	code := C.MPIN_BN254_GET_CLIENT_PERMIT(C.int(h), C.int(d), (*C.octet)(S), (*C.octet)(ID), (*C.octet)(TP))
	return newError(int(code))
}

// MPIN_BN254CX_GET_CLIENT_PERMIT is a go wrapper for C.MPIN_BN254CX_GET_CLIENT_PERMIT
func MPIN_BN254CX_GET_CLIENT_PERMIT(h int, d int, S *Octet, ID *Octet, TP *Octet) error {
	code := C.MPIN_BN254CX_GET_CLIENT_PERMIT(C.int(h), C.int(d), (*C.octet)(S), (*C.octet)(ID), (*C.octet)(TP))
	return newError(int(code))
}

// MPIN_BLS383_GET_CLIENT_SECRET is a go wrapper for C.MPIN_BLS383_GET_CLIENT_SECRET
func MPIN_BLS383_GET_CLIENT_SECRET(S *Octet, ID *Octet, CS *Octet) error {
	code := C.MPIN_BLS383_GET_CLIENT_SECRET((*C.octet)(S), (*C.octet)(ID), (*C.octet)(CS))
	return newError(int(code))
}

// MPIN_BN254_GET_CLIENT_SECRET is a go wrapper for C.MPIN_BN254_GET_CLIENT_SECRET
func MPIN_BN254_GET_CLIENT_SECRET(S *Octet, ID *Octet, CS *Octet) error {
	code := C.MPIN_BN254_GET_CLIENT_SECRET((*C.octet)(S), (*C.octet)(ID), (*C.octet)(CS))
	return newError(int(code))
}

// MPIN_BN254CX_GET_CLIENT_SECRET is a go wrapper for C.MPIN_BN254CX_GET_CLIENT_SECRET
func MPIN_BN254CX_GET_CLIENT_SECRET(S *Octet, ID *Octet, CS *Octet) error {
	code := C.MPIN_BN254CX_GET_CLIENT_SECRET((*C.octet)(S), (*C.octet)(ID), (*C.octet)(CS))
	return newError(int(code))
}

// MPIN_BLS383_GET_DVS_KEYPAIR is a go wrapper for C.MPIN_BLS383_GET_DVS_KEYPAIR
func MPIN_BLS383_GET_DVS_KEYPAIR(R *Rand, Z *Octet, Pa *Octet) error {
	code := C.MPIN_BLS383_GET_DVS_KEYPAIR((*C.csprng)(R), (*C.octet)(Z), (*C.octet)(Pa))
	return newError(int(code))
}

// MPIN_BN254_GET_DVS_KEYPAIR is a go wrapper for C.MPIN_BN254_GET_DVS_KEYPAIR
func MPIN_BN254_GET_DVS_KEYPAIR(R *Rand, Z *Octet, Pa *Octet) error {
	code := C.MPIN_BN254_GET_DVS_KEYPAIR((*C.csprng)(R), (*C.octet)(Z), (*C.octet)(Pa))
	return newError(int(code))
}

// MPIN_BN254CX_GET_DVS_KEYPAIR is a go wrapper for C.MPIN_BN254CX_GET_DVS_KEYPAIR
func MPIN_BN254CX_GET_DVS_KEYPAIR(R *Rand, Z *Octet, Pa *Octet) error {
	code := C.MPIN_BN254CX_GET_DVS_KEYPAIR((*C.csprng)(R), (*C.octet)(Z), (*C.octet)(Pa))
	return newError(int(code))
}

// MPIN_BLS383_GET_G1_MULTIPLE is a go wrapper for C.MPIN_BLS383_GET_G1_MULTIPLE
func MPIN_BLS383_GET_G1_MULTIPLE(R *Rand, t int, x *Octet, G *Octet, W *Octet) error {
	code := C.MPIN_BLS383_GET_G1_MULTIPLE((*C.csprng)(R), C.int(t), (*C.octet)(x), (*C.octet)(G), (*C.octet)(W))
	return newError(int(code))
}

// MPIN_BN254_GET_G1_MULTIPLE is a go wrapper for C.MPIN_BN254_GET_G1_MULTIPLE
func MPIN_BN254_GET_G1_MULTIPLE(R *Rand, t int, x *Octet, G *Octet, W *Octet) error {
	code := C.MPIN_BN254_GET_G1_MULTIPLE((*C.csprng)(R), C.int(t), (*C.octet)(x), (*C.octet)(G), (*C.octet)(W))
	return newError(int(code))
}

// MPIN_BN254CX_GET_G1_MULTIPLE is a go wrapper for C.MPIN_BN254CX_GET_G1_MULTIPLE
func MPIN_BN254CX_GET_G1_MULTIPLE(R *Rand, t int, x *Octet, G *Octet, W *Octet) error {
	code := C.MPIN_BN254CX_GET_G1_MULTIPLE((*C.csprng)(R), C.int(t), (*C.octet)(x), (*C.octet)(G), (*C.octet)(W))
	return newError(int(code))
}

// MPIN_BLS383_GET_SERVER_SECRET is a go wrapper for C.MPIN_BLS383_GET_SERVER_SECRET
func MPIN_BLS383_GET_SERVER_SECRET(S *Octet, SS *Octet) error {
	code := C.MPIN_BLS383_GET_SERVER_SECRET((*C.octet)(S), (*C.octet)(SS))
	return newError(int(code))
}

// MPIN_BN254_GET_SERVER_SECRET is a go wrapper for C.MPIN_BN254_GET_SERVER_SECRET
func MPIN_BN254_GET_SERVER_SECRET(S *Octet, SS *Octet) error {
	code := C.MPIN_BN254_GET_SERVER_SECRET((*C.octet)(S), (*C.octet)(SS))
	return newError(int(code))
}

// MPIN_BN254CX_GET_SERVER_SECRET is a go wrapper for C.MPIN_BN254CX_GET_SERVER_SECRET
func MPIN_BN254CX_GET_SERVER_SECRET(S *Octet, SS *Octet) error {
	code := C.MPIN_BN254CX_GET_SERVER_SECRET((*C.octet)(S), (*C.octet)(SS))
	return newError(int(code))
}

// MPIN_BLS383_KANGAROO is a go wrapper for C.MPIN_BLS383_KANGAROO
func MPIN_BLS383_KANGAROO(E *Octet, F *Octet) error {
	code := C.MPIN_BLS383_KANGAROO((*C.octet)(E), (*C.octet)(F))
	return newError(int(code))
}

// MPIN_BN254_KANGAROO is a go wrapper for C.MPIN_BN254_KANGAROO
func MPIN_BN254_KANGAROO(E *Octet, F *Octet) error {
	code := C.MPIN_BN254_KANGAROO((*C.octet)(E), (*C.octet)(F))
	return newError(int(code))
}

// MPIN_BN254CX_KANGAROO is a go wrapper for C.MPIN_BN254CX_KANGAROO
func MPIN_BN254CX_KANGAROO(E *Octet, F *Octet) error {
	code := C.MPIN_BN254CX_KANGAROO((*C.octet)(E), (*C.octet)(F))
	return newError(int(code))
}

// MPIN_BLS383_PRECOMPUTE is a go wrapper for C.MPIN_BLS383_PRECOMPUTE
func MPIN_BLS383_PRECOMPUTE(T *Octet, ID *Octet, CP *Octet, g1 *Octet, g2 *Octet) error {
	code := C.MPIN_BLS383_PRECOMPUTE((*C.octet)(T), (*C.octet)(ID), (*C.octet)(CP), (*C.octet)(g1), (*C.octet)(g2))
	return newError(int(code))
}

// MPIN_BN254_PRECOMPUTE is a go wrapper for C.MPIN_BN254_PRECOMPUTE
func MPIN_BN254_PRECOMPUTE(T *Octet, ID *Octet, CP *Octet, g1 *Octet, g2 *Octet) error {
	code := C.MPIN_BN254_PRECOMPUTE((*C.octet)(T), (*C.octet)(ID), (*C.octet)(CP), (*C.octet)(g1), (*C.octet)(g2))
	return newError(int(code))
}

// MPIN_BN254CX_PRECOMPUTE is a go wrapper for C.MPIN_BN254CX_PRECOMPUTE
func MPIN_BN254CX_PRECOMPUTE(T *Octet, ID *Octet, CP *Octet, g1 *Octet, g2 *Octet) error {
	code := C.MPIN_BN254CX_PRECOMPUTE((*C.octet)(T), (*C.octet)(ID), (*C.octet)(CP), (*C.octet)(g1), (*C.octet)(g2))
	return newError(int(code))
}

// MPIN_BLS383_RANDOM_GENERATE is a go wrapper for C.MPIN_BLS383_RANDOM_GENERATE
func MPIN_BLS383_RANDOM_GENERATE(R *Rand, S *Octet) error {
	code := C.MPIN_BLS383_RANDOM_GENERATE((*C.csprng)(R), (*C.octet)(S))
	return newError(int(code))
}

// MPIN_BN254_RANDOM_GENERATE is a go wrapper for C.MPIN_BN254_RANDOM_GENERATE
func MPIN_BN254_RANDOM_GENERATE(R *Rand, S *Octet) error {
	code := C.MPIN_BN254_RANDOM_GENERATE((*C.csprng)(R), (*C.octet)(S))
	return newError(int(code))
}

// MPIN_BN254CX_RANDOM_GENERATE is a go wrapper for C.MPIN_BN254CX_RANDOM_GENERATE
func MPIN_BN254CX_RANDOM_GENERATE(R *Rand, S *Octet) error {
	code := C.MPIN_BN254CX_RANDOM_GENERATE((*C.csprng)(R), (*C.octet)(S))
	return newError(int(code))
}

// MPIN_BLS383_RECOMBINE_G1 is a go wrapper for C.MPIN_BLS383_RECOMBINE_G1
func MPIN_BLS383_RECOMBINE_G1(Q1 *Octet, Q2 *Octet, Q *Octet) error {
	code := C.MPIN_BLS383_RECOMBINE_G1((*C.octet)(Q1), (*C.octet)(Q2), (*C.octet)(Q))
	return newError(int(code))
}

// MPIN_BN254_RECOMBINE_G1 is a go wrapper for C.MPIN_BN254_RECOMBINE_G1
func MPIN_BN254_RECOMBINE_G1(Q1 *Octet, Q2 *Octet, Q *Octet) error {
	code := C.MPIN_BN254_RECOMBINE_G1((*C.octet)(Q1), (*C.octet)(Q2), (*C.octet)(Q))
	return newError(int(code))
}

// MPIN_BN254CX_RECOMBINE_G1 is a go wrapper for C.MPIN_BN254CX_RECOMBINE_G1
func MPIN_BN254CX_RECOMBINE_G1(Q1 *Octet, Q2 *Octet, Q *Octet) error {
	code := C.MPIN_BN254CX_RECOMBINE_G1((*C.octet)(Q1), (*C.octet)(Q2), (*C.octet)(Q))
	return newError(int(code))
}

// MPIN_BLS383_RECOMBINE_G2 is a go wrapper for C.MPIN_BLS383_RECOMBINE_G2
func MPIN_BLS383_RECOMBINE_G2(P1 *Octet, P2 *Octet, P *Octet) error {
	code := C.MPIN_BLS383_RECOMBINE_G2((*C.octet)(P1), (*C.octet)(P2), (*C.octet)(P))
	return newError(int(code))
}

// MPIN_BN254_RECOMBINE_G2 is a go wrapper for C.MPIN_BN254_RECOMBINE_G2
func MPIN_BN254_RECOMBINE_G2(P1 *Octet, P2 *Octet, P *Octet) error {
	code := C.MPIN_BN254_RECOMBINE_G2((*C.octet)(P1), (*C.octet)(P2), (*C.octet)(P))
	return newError(int(code))
}

// MPIN_BN254CX_RECOMBINE_G2 is a go wrapper for C.MPIN_BN254CX_RECOMBINE_G2
func MPIN_BN254CX_RECOMBINE_G2(P1 *Octet, P2 *Octet, P *Octet) error {
	code := C.MPIN_BN254CX_RECOMBINE_G2((*C.octet)(P1), (*C.octet)(P2), (*C.octet)(P))
	return newError(int(code))
}

// MPIN_BLS383_SERVER_2 is a go wrapper for C.MPIN_BLS383_SERVER_2
func MPIN_BLS383_SERVER_2(d int, HID *Octet, HTID *Octet, y *Octet, SS *Octet, U *Octet, UT *Octet, V *Octet, E *Octet, F *Octet, Pa *Octet) error {
	code := C.MPIN_BLS383_SERVER_2(C.int(d), (*C.octet)(HID), (*C.octet)(HTID), (*C.octet)(y), (*C.octet)(SS), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(V), (*C.octet)(E), (*C.octet)(F), (*C.octet)(Pa))
	return newError(int(code))
}

// MPIN_BN254_SERVER_2 is a go wrapper for C.MPIN_BN254_SERVER_2
func MPIN_BN254_SERVER_2(d int, HID *Octet, HTID *Octet, y *Octet, SS *Octet, U *Octet, UT *Octet, V *Octet, E *Octet, F *Octet, Pa *Octet) error {
	code := C.MPIN_BN254_SERVER_2(C.int(d), (*C.octet)(HID), (*C.octet)(HTID), (*C.octet)(y), (*C.octet)(SS), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(V), (*C.octet)(E), (*C.octet)(F), (*C.octet)(Pa))
	return newError(int(code))
}

// MPIN_BN254CX_SERVER_2 is a go wrapper for C.MPIN_BN254CX_SERVER_2
func MPIN_BN254CX_SERVER_2(d int, HID *Octet, HTID *Octet, y *Octet, SS *Octet, U *Octet, UT *Octet, V *Octet, E *Octet, F *Octet, Pa *Octet) error {
	code := C.MPIN_BN254CX_SERVER_2(C.int(d), (*C.octet)(HID), (*C.octet)(HTID), (*C.octet)(y), (*C.octet)(SS), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(V), (*C.octet)(E), (*C.octet)(F), (*C.octet)(Pa))
	return newError(int(code))
}

// MPIN_BLS383_SERVER_KEY is a go wrapper for C.MPIN_BLS383_SERVER_KEY
func MPIN_BLS383_SERVER_KEY(h int, Z *Octet, SS *Octet, w *Octet, p *Octet, I *Octet, U *Octet, UT *Octet, K *Octet) error {
	code := C.MPIN_BLS383_SERVER_KEY(C.int(h), (*C.octet)(Z), (*C.octet)(SS), (*C.octet)(w), (*C.octet)(p), (*C.octet)(I), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(K))
	return newError(int(code))
}

// MPIN_BN254_SERVER_KEY is a go wrapper for C.MPIN_BN254_SERVER_KEY
func MPIN_BN254_SERVER_KEY(h int, Z *Octet, SS *Octet, w *Octet, p *Octet, I *Octet, U *Octet, UT *Octet, K *Octet) error {
	code := C.MPIN_BN254_SERVER_KEY(C.int(h), (*C.octet)(Z), (*C.octet)(SS), (*C.octet)(w), (*C.octet)(p), (*C.octet)(I), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(K))
	return newError(int(code))
}

// MPIN_BN254CX_SERVER_KEY is a go wrapper for C.MPIN_BN254CX_SERVER_KEY
func MPIN_BN254CX_SERVER_KEY(h int, Z *Octet, SS *Octet, w *Octet, p *Octet, I *Octet, U *Octet, UT *Octet, K *Octet) error {
	code := C.MPIN_BN254CX_SERVER_KEY(C.int(h), (*C.octet)(Z), (*C.octet)(SS), (*C.octet)(w), (*C.octet)(p), (*C.octet)(I), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(K))
	return newError(int(code))
}

// MPIN_BLS383_SERVER is a go wrapper for C.MPIN_BLS383_SERVER
func MPIN_BLS383_SERVER(h int, d int, HID *Octet, HTID *Octet, y *Octet, SS *Octet, U *Octet, UT *Octet, V *Octet, E *Octet, F *Octet, ID *Octet, MESSAGE *Octet, t int, Pa *Octet) error {
	code := C.MPIN_BLS383_SERVER(C.int(h), C.int(d), (*C.octet)(HID), (*C.octet)(HTID), (*C.octet)(y), (*C.octet)(SS), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(V), (*C.octet)(E), (*C.octet)(F), (*C.octet)(ID), (*C.octet)(MESSAGE), C.int(t), (*C.octet)(Pa))
	return newError(int(code))
}

// MPIN_BN254_SERVER is a go wrapper for C.MPIN_BN254_SERVER
func MPIN_BN254_SERVER(h int, d int, HID *Octet, HTID *Octet, y *Octet, SS *Octet, U *Octet, UT *Octet, V *Octet, E *Octet, F *Octet, ID *Octet, MESSAGE *Octet, t int, Pa *Octet) error {
	code := C.MPIN_BN254_SERVER(C.int(h), C.int(d), (*C.octet)(HID), (*C.octet)(HTID), (*C.octet)(y), (*C.octet)(SS), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(V), (*C.octet)(E), (*C.octet)(F), (*C.octet)(ID), (*C.octet)(MESSAGE), C.int(t), (*C.octet)(Pa))
	return newError(int(code))
}

// MPIN_BN254CX_SERVER is a go wrapper for C.MPIN_BN254CX_SERVER
func MPIN_BN254CX_SERVER(h int, d int, HID *Octet, HTID *Octet, y *Octet, SS *Octet, U *Octet, UT *Octet, V *Octet, E *Octet, F *Octet, ID *Octet, MESSAGE *Octet, t int, Pa *Octet) error {
	code := C.MPIN_BN254CX_SERVER(C.int(h), C.int(d), (*C.octet)(HID), (*C.octet)(HTID), (*C.octet)(y), (*C.octet)(SS), (*C.octet)(U), (*C.octet)(UT), (*C.octet)(V), (*C.octet)(E), (*C.octet)(F), (*C.octet)(ID), (*C.octet)(MESSAGE), C.int(t), (*C.octet)(Pa))
	return newError(int(code))
}

// MPIN_BLS383_SERVER_1 is a go wrapper for C.MPIN_BLS383_SERVER_1
func MPIN_BLS383_SERVER_1(h int, d int, ID *Octet, HID *Octet, HTID *Octet) {
	C.MPIN_BLS383_SERVER_1(C.int(h), C.int(d), (*C.octet)(ID), (*C.octet)(HID), (*C.octet)(HTID))
}

// MPIN_BN254_SERVER_1 is a go wrapper for C.MPIN_BN254_SERVER_1
func MPIN_BN254_SERVER_1(h int, d int, ID *Octet, HID *Octet, HTID *Octet) {
	C.MPIN_BN254_SERVER_1(C.int(h), C.int(d), (*C.octet)(ID), (*C.octet)(HID), (*C.octet)(HTID))
}

// MPIN_BN254CX_SERVER_1 is a go wrapper for C.MPIN_BN254CX_SERVER_1
func MPIN_BN254CX_SERVER_1(h int, d int, ID *Octet, HID *Octet, HTID *Octet) {
	C.MPIN_BN254CX_SERVER_1(C.int(h), C.int(d), (*C.octet)(ID), (*C.octet)(HID), (*C.octet)(HTID))
}
