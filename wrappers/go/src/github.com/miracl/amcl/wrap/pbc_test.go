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
	"encoding/hex"
	"fmt"
	"testing"
)

const nIter int = 100

func TestOctets(t *testing.T) {
	// Test bad hex
	oct := GetOctetHex("zz")
	if int(oct.len) != 0 {
		t.Errorf("invalid hex length; len=%v; expected=%v", int(oct.len), 0)
	}

	// Test good hex
	oct = GetOctetHex("30")
	if int(oct.len) != 1 {
		t.Errorf("invalid hex length; len=%v; expected=%v", int(oct.len), 1)
	}

	oct = GetOctetHex("30")
	if int(*oct.val) != 48 {
		t.Errorf("invalid hex length; len=%v; expected=%v", int(oct.len), 48)
	}

	e := "010203"
	c := GetOctet(string([]byte{1, 2, 3}))
	h := OctetToHex(&c)
	if h != e {
		t.Errorf("OctetToHex failed; got=h; expected=%v", e)
	}

	rtn := OctetComp([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	if rtn != 1 {
		t.Errorf("unexpected return code; rtn=%v; expected=%v", rtn, 1)
	}

	expected := "\x01\x02\x03"
	s := OctetToString(&c)
	if s != expected {
		t.Errorf("octet convertion failed; %v != %v", s, expected)
	}
}

func TestGenerateRandomByte(t *testing.T) {
	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := NewRand(seed)

	expected := "57d662d39b1b245da469"
	b := GenerateRandomByte(rng, 10)
	if fmt.Sprintf("%x", b) != expected {
		t.Errorf("random byte generation failed; %x != %v", b, expected)
	}
}

func TestGenerateOTP(t *testing.T) {
	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := NewRand(seed)

	expected := 715827
	otp := GenerateOTP(rng)
	if otp != expected {
		t.Errorf("OTP generation failed; %v != %v", otp, expected)
	}
}

func TestAesGcm(t *testing.T) {
	testCases := []struct {
		Key       string
		IV        string
		AAD       string
		PlainText string
		outC      string
		outT      string
	}{
		{
			Key:       "75eae8f5ec7a5c8882f4a389600da8cd",
			IV:        "a231cd40fdb909ad11c457d9",
			AAD:       "a50d3e45b23c77157cb0e01c2a679e6d99c038e4",
			PlainText: "45cf12964fc824ab76616ae2f4bf0822",
			outC:      "5df1c20786beb4dc24bab9caf2ad3a03",
			outT:      "ba8036433389c88b79e277f49a4bc41d",
		},
	}

	hexDecode := func(s string) []byte {
		k, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal("Decode hex error")
		}
		return k
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("Case %v", i), func(t *testing.T) {
			C, T, err := AesGcmEncrypt(hexDecode(tc.Key), hexDecode(tc.IV), hexDecode(tc.AAD), hexDecode(tc.PlainText))
			if err != nil {
				t.Fatal("Fatal error on AES Key length")
			}
			if hex.EncodeToString(C) != tc.outC || hex.EncodeToString(T) != tc.outT {
				t.Errorf("AES GCM encryption failed; {C:%v, T:%v} != {C:%v, T:%v}",
					hex.EncodeToString(C), hex.EncodeToString(T),
					tc.outC, tc.outT,
				)
			}

			dP, dT, err := AesGcmDecrypt(hexDecode(tc.Key), hexDecode(tc.IV), hexDecode(tc.AAD), hexDecode(tc.outC))
			if err != nil {
				t.Fatalf("AES GCM decrypt failed; err = %v;", err)
			}
			if hex.EncodeToString(dP) != tc.PlainText || hex.EncodeToString(dT) != tc.outT {
				t.Errorf("AES GCM decrypt failed; {P:%v, T:%v} != {P:%v, T:%v}",
					hex.EncodeToString(dP), hex.EncodeToString(dT),
					tc.PlainText, tc.outT,
				)
			}
		})
	}
}

func TestBadAesGcm(t *testing.T) {
	testCases := []struct {
		Key       string
		IV        string
		AAD       string
		PlainText string
		outC      string
	}{
		{
			Key:       "75eae8f5ec7a5c88",
			IV:        "a231cd40fdb909ad11c457d9",
			AAD:       "a50d3e45b23c77157cb0e01c2a679e6d99c038e4",
			PlainText: "45cf12964fc824ab76616ae2f4bf0822",
			outC:      "5df1c20786beb4dc24bab9caf2ad3a03",
		},
		{
			Key:       "75eae8f5ec7a5c8875eae8f5ec7a5c8875eae8f5ec7a5c88",
			IV:        "a231cd40fdb909ad11c457d9",
			AAD:       "a50d3e45b23c77157cb0e01c2a679e6d99c038e4",
			PlainText: "45cf12964fc824ab76616ae2f4bf0822",
			outC:      "5df1c20786beb4dc24bab9caf2ad3a03",
		},
	}

	hexDecode := func(s string) []byte {
		k, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal("Decode hex error")
		}
		return k
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("Case %v", i), func(t *testing.T) {
			_, _, err := AesGcmEncrypt(hexDecode(tc.Key), hexDecode(tc.IV), hexDecode(tc.AAD), hexDecode(tc.PlainText))
			if err == nil {
				t.Fatal("Fatal error on AES Key length")
			}

			_, _, err = AesGcmDecrypt(hexDecode(tc.Key), hexDecode(tc.IV), hexDecode(tc.AAD), hexDecode(tc.outC))
			if err == nil {
				t.Fatal("Fatal error on AES Key length")
			}
		})
	}
}
