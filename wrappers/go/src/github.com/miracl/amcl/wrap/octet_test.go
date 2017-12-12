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
	"reflect"
	"testing"
)

func TestOctet(t *testing.T) {
	m := []byte("not very long message")
	src := newOctet(m)

	slice := make([]byte, len(m))
	dst := makeOctet(slice)
	copyOctet(dst, src)

	if dst.len != src.len || dst.max != src.max || !reflect.DeepEqual(slice, m) {
		t.Fatalf("slices are not equal; %v != %v", slice, m)
	}
}

func BenchmarkOctet(b *testing.B) {
	m := []byte("not very long message")

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			slice := make([]byte, len(m))
			copyOctet(makeOctet(slice), newOctet(m))
		}
	})
}
