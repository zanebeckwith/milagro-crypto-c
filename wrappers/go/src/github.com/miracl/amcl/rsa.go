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

//go:generate go run gen/rsa/main.go

// #include "rsa_support.h"
// #include "wrappers_generated.h"
import "C"
import "bytes"

// RSA Constant
const MAX_RSA_BYTES int = int(C.MAX_RSA_BYTES) // MAX_RSA_BYTES is the maximum RSA level of security supported - 4096

type RSAPrivateKey interface{}

type RSAPublicKey interface{}

// PKCS15 (PKCS 1.5) - padding of a message to be signed
func PKCS15OLD(hashType, rfs int, msg []byte) ([]byte, error) {
	r := make([]byte, rfs)
	rtn := C._PKCS15(C.int(hashType), *newOctet(msg), *makeOctet(r))
	return r, newError(int(rtn))
}

// OAEPencode encodes the message for encryption
func OAEPencode(hashType, rfs int, m []byte, rng *Rand, p []byte) ([]byte, error) {
	f := make([]byte, rfs)
	rtn := C._OAEP_ENCODE(C.int(hashType), *newOctet(m), rng.csprng(), *newOctet(p), *makeOctet(f))
	return f, newError(int(rtn))
}

// OAEPdecode decodes message M after decryption, F is the decoded message
func OAEPdecode(hashType int, p []byte, m []byte) ([]byte, error) {
	rtn := C._OAEP_DECODE(C.int(hashType), *newOctet(p), *newOctet(m))
	return bytes.TrimRight(m, "\x00"), newError(int(rtn))
}
