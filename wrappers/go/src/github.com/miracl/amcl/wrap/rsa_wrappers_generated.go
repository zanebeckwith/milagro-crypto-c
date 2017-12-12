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

// #include "rsa_support.h"
import "C"

// PKCS15 is a go wrapper for C.PKCS15
func PKCS15(h int, m *Octet, w *Octet) error {
	code := C.PKCS15(C.int(h), (*C.octet)(m), (*C.octet)(w))
	return newError(code)
}

// OAEP_ENCODE is a go wrapper for C.OAEP_ENCODE
func OAEP_ENCODE(h int, m *Octet, rng *Rand, p *Octet, f *Octet) error {
	code := C.OAEP_ENCODE(C.int(h), (*C.octet)(m), (*C.csprng)(rng), (*C.octet)(p), (*C.octet)(f))
	return newError(code)
}

// OAEP_DECODE is a go wrapper for C.OAEP_DECODE
func OAEP_DECODE(h int, p *Octet, f *Octet) error {
	code := C.OAEP_DECODE(C.int(h), (*C.octet)(p), (*C.octet)(f))
	return newError(code)
}