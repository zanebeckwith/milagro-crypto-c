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

import (
	"bytes"
	"io"
	"testing"
)

func TestRand(t *testing.T) {
	rand := NewRand([]byte("seed"))

	results := [][]byte{
		[]byte{0xd0, 0xf, 0xb, 0x37, 0x59},
		[]byte{0x56, 0x2b, 0x46, 0x7, 0x35},
		[]byte{0xe9, 0x47, 0xd4, 0x95, 0x7e},
		[]byte{0x4c, 0xea, 0xe4, 0x9c, 0xd1},
		[]byte{0xf5, 0x11, 0x36, 0xab, 0x83},
	}

	randomNum := make([]byte, 5)
	for _, expectedNum := range results {
		io.ReadFull(rand, randomNum)

		if !bytes.Equal(randomNum, expectedNum) {
			t.Error("error")
		}
	}
}

func BenchmarkNewRand(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			NewRand([]byte("seed"))
		}
	})
}

func BenchmarkRandRead(b *testing.B) {
	rand := NewRand([]byte("seed"))
	num := make([]byte, 5)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			io.ReadFull(rand, num)
		}
	})
}
