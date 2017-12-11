// Licensed to `the Apache Software Foundation (ASF) under one
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

// #include "amcl.h"
// #include "stdlib.h"
// #include "string.h"
import "C"
import "unsafe"

// Octet is Go alias for the C octet type
type Octet C.octet

// NewOctet creates new Octet with given value
func NewOctet(val []byte) *Octet {
	return &Octet{
		len: C.int(len(val)),
		max: C.int(len(val)),
		val: C.CString(string(val)),
	}
}

// MakeOctet create empty Octet
func MakeOctet(max int) *Octet {
	return &Octet{
		len: 0,
		max: C.int(max),
		val: (*C.char)(C.malloc(C.size_t(max))),
	}
}

// ToBytes returns the bytes representation of the Octet
func (o *Octet) ToBytes() []byte {
	return C.GoBytes(unsafe.Pointer(o.val), o.len)
}

// Free frees the allocated memory
func (o *Octet) Free() {
	C.free(unsafe.Pointer(o.val))
}

// TODO: func (o *Octet) Free()

func newOctet(val []byte) *C.octet {
	if val == nil {
		return &C.octet{}
	}

	return &C.octet{
		C.int(len(val)),
		C.int(len(val)),
		(*C.char)(unsafe.Pointer(&val[0])),
	}
}

func makeOctet(val []byte) *C.octet {
	return &C.octet{
		C.int(0),
		C.int(len(val)),
		(*C.char)(unsafe.Pointer(&val[0])),
	}
}

func copyOctet(dst, src *C.octet) {
	dst.len = src.len
	dst.max = src.max
	C.strcpy(dst.val, src.val)
}
