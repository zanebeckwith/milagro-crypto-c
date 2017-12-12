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

package wrap

// #include "amcl.h"
// #include "randapi.h"
// #include "wrappers_generated.h"
import "C"

// Rand is a cryptographically secure random number generator
type Rand C.csprng

// NewRand create new seeded Rand
func NewRand(seed []byte) *Rand {
	var rand C.csprng
	C._CREATE_CSPRNG(&rand, *newOctet(seed))
	return (*Rand)(&rand)
}

// GetByte returns one random byte
func (rand *Rand) GetByte() byte {
	r := C.RAND_byte((*C.csprng)(rand))
	return byte(r)
}

// Read generates len(p) random bytes and writes them into p. It
// always returns len(p) and a nil error.
// Read should not be called concurrently with any other Rand method.
func (rand *Rand) Read(p []byte) (n int, err error) {
	for x := 0; x < len(p); x++ {
		p[x] = rand.GetByte()
	}

	return len(p), nil
}

func (rand *Rand) csprng() *C.csprng {
	return (*C.csprng)(rand)
}
