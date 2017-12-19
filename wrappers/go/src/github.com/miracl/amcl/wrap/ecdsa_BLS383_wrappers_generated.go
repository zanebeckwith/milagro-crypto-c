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

// #cgo LDFLAGS: -lamcl_curve_BLS383
// #include <stdio.h>
// #include <stdlib.h>
// #include "amcl.h"
// #include "ecdh_BLS383.h"
import "C"

const (
	EFS_BLS383 = int(C.EFS_BLS383) // EFS is the ECC Field Size in bytes
	EGS_BLS383 = int(C.EGS_BLS383) // EGS is the ECC Group Size in bytes
)

// ECP_BLS383_KEY_PAIR_GENERATE is a go wrapper for C.ECP_BLS383_KEY_PAIR_GENERATE
func ECP_BLS383_KEY_PAIR_GENERATE(R *Rand, s *Octet, W *Octet) error {
	code := C.ECP_BLS383_KEY_PAIR_GENERATE((*C.csprng)(R), (*C.octet)(s), (*C.octet)(W))
	return newError(code)
}

// ECP_BLS383_PUBLIC_KEY_VALIDATE is a go wrapper for C.ECP_BLS383_PUBLIC_KEY_VALIDATE
func ECP_BLS383_PUBLIC_KEY_VALIDATE(W *Octet) error {
	code := C.ECP_BLS383_PUBLIC_KEY_VALIDATE((*C.octet)(W))
	return newError(code)
}

// ECP_BLS383_SP_DSA is a go wrapper for C.ECP_BLS383_SP_DSA
func ECP_BLS383_SP_DSA(h int, R *Rand, k *Octet, s *Octet, M *Octet, c *Octet, d *Octet) error {
	code := C.ECP_BLS383_SP_DSA(C.int(h), (*C.csprng)(R), (*C.octet)(k), (*C.octet)(s), (*C.octet)(M), (*C.octet)(c), (*C.octet)(d))
	return newError(code)
}

// ECP_BLS383_VP_DSA is a go wrapper for C.ECP_BLS383_VP_DSA
func ECP_BLS383_VP_DSA(h int, W *Octet, M *Octet, c *Octet, d *Octet) error {
	code := C.ECP_BLS383_VP_DSA(C.int(h), (*C.octet)(W), (*C.octet)(M), (*C.octet)(c), (*C.octet)(d))
	return newError(code)
}
