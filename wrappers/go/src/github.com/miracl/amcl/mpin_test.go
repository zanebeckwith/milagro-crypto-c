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

import (
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"testing"
)

var mPinTestCases = []struct {
	curve                  string
	PFS                    int
	G1S                    int
	PGS                    int
	rng                    func(RNG *Rand) (errorCode int, S []byte)
	getDVSKeyPair          func(RNG *Rand, z []byte) (errorCode int, zOut []byte, publicKey []byte)
	getServerSecret        func(masterSecret []byte) (errorCode int, serverSecret []byte)
	recombineServerSecret  func(W1 []byte, W2 []byte) (errorCode int, W []byte)
	getClientSecret        func(masterSecret []byte, hashMPinId []byte) (errorCode int, clientSecret []byte)
	recombineClientSecret  func(R1 []byte, R2 []byte) (errorCode int, R []byte)
	getKeyEscrowLessSecret func(RNG *Rand, typ int, x []byte, G []byte) (errorCode int, xOut, W []byte)
	extractPin             func(hashType int, mpinId []byte, PIN int, clientSecret []byte) (errorCode int, token []byte)
	client                 func(hashType, epochDate int, mpinId []byte, RNG *Rand, x []byte, PIN int, token []byte, timePermit []byte, message []byte, epochTime int) (errorCode int, xOut, y, V, U, UT []byte)
	server                 func(hashType, epochDate, epochTime int, serverSecret, U, UT, V, mpinId, publicKey, message []byte, Kangaroo bool) (errorCode int, HID, HTID, y, E, F []byte)
	clientPass1            func(hashType, epochDate int, mpinId []byte, RNG *Rand, x []byte, PIN int, token []byte, timePermit []byte) (errorCode int, xOut, SEC, U, UT []byte)
	serverPass1            func(hashType, epochDate int, mpinId []byte) (HID, HTID []byte)
	clientPass2            func(x []byte, y []byte, SEC []byte) (errorCode int, V []byte)
	serverPass2            func(epochDate int, HID []byte, HTID []byte, publicKey []byte, y []byte, serverSecret []byte, U []byte, UT []byte, V []byte, Kangaroo_BN254 bool) (errorCode int, E []byte, F []byte)
	getClientPermit        func(hashType, epochDate int, masterSecret, hashMPinId []byte) (errorCode int, timePermit []byte)
}{
	{
		curve:                  "BLS383",
		PFS:                    PFS_BLS383,
		G1S:                    G1S_BLS383,
		PGS:                    PGS_BLS383,
		rng:                    RandomGenerate_BLS383,
		getDVSKeyPair:          GetDVSKeyPair_BLS383,
		getServerSecret:        GetServerSecret_BLS383,
		recombineServerSecret:  RecombineG2_BLS383,
		getClientSecret:        GetClientSecret_BLS383,
		recombineClientSecret:  RecombineG1_BLS383,
		getKeyEscrowLessSecret: GetG1Multiple_BLS383,
		extractPin:             ExtractPIN_BLS383,
		client:                 Client_BLS383,
		server:                 Server_BLS383,
		clientPass1:            Client1_BLS383,
		serverPass1:            Server1_BLS383,
		clientPass2:            Client2_BLS383,
		serverPass2:            Server2_BLS383,
		getClientPermit:        GetClientPermit_BLS383,
	},
	{
		curve:                  "BN254",
		PFS:                    PFS_BN254,
		G1S:                    G1S_BN254,
		PGS:                    PGS_BN254,
		rng:                    RandomGenerate_BN254,
		getDVSKeyPair:          GetDVSKeyPair_BN254,
		getServerSecret:        GetServerSecret_BN254,
		recombineServerSecret:  RecombineG2_BN254,
		getClientSecret:        GetClientSecret_BN254,
		recombineClientSecret:  RecombineG1_BN254,
		getKeyEscrowLessSecret: GetG1Multiple_BN254,
		extractPin:             ExtractPIN_BN254,
		client:                 Client_BN254,
		server:                 Server_BN254,
		clientPass1:            Client1_BN254,
		serverPass1:            Server1_BN254,
		clientPass2:            Client2_BN254,
		serverPass2:            Server2_BN254,
		getClientPermit:        GetClientPermit_BN254,
	},
	{
		curve:                  "BN254CX",
		PFS:                    PFS_BN254CX,
		G1S:                    G1S_BN254CX,
		PGS:                    PGS_BN254CX,
		rng:                    RandomGenerate_BN254CX,
		getDVSKeyPair:          GetDVSKeyPair_BN254CX,
		getServerSecret:        GetServerSecret_BN254CX,
		recombineServerSecret:  RecombineG2_BN254CX,
		getClientSecret:        GetClientSecret_BN254CX,
		recombineClientSecret:  RecombineG1_BN254CX,
		getKeyEscrowLessSecret: GetG1Multiple_BN254CX,
		extractPin:             ExtractPIN_BN254CX,
		client:                 Client_BN254CX,
		server:                 Server_BN254CX,
		clientPass1:            Client1_BN254CX,
		serverPass1:            Server1_BN254CX,
		clientPass2:            Client2_BN254CX,
		serverPass2:            Server2_BN254CX,
		getClientPermit:        GetClientPermit_BN254CX,
	},
}

func TestKeyEscrowLess(t *testing.T) {
	for _, tc := range mPinTestCases {
		t.Run(tc.curve, func(t *testing.T) {
			// Assign the End-User an ID
			IDstr := "testUser@miracl.com"
			ID := []byte(IDstr)

			// Epoch time in days
			date := 0

			// Epoch time in seconds
			timeValue := 1439465203

			// PIN variable to create token
			PIN1 := 1234
			// PIN variable to authenticate
			PIN2 := 1234

			// Seed value for Random Number Generator (RNG)
			seedHex := "ac4509d6"
			seed, err := hex.DecodeString(seedHex)
			if err != nil {
				fmt.Println("Error decoding seed value")
				return
			}
			rng := NewRand(seed)

			// Generate Master Secret Share 1
			_, MS1 := tc.rng(rng)

			// Destroy MS1
			defer CleanMemory(MS1[:])

			// Generate Master Secret Share 2
			_, MS2 := tc.rng(rng)

			// Destroy MS2
			defer CleanMemory(MS2[:])

			// Generate Public Key
			_, Z := tc.rng(rng)
			_, _, Pa := tc.getDVSKeyPair(nil, Z[:])

			// Destroy Z
			defer CleanMemory(Z[:])

			// Compute ID|Pa
			ID = append(ID, Pa...)

			// Either Client or TA calculates Hash(ID)
			HCID := HashId(HASH_TYPE_MPIN, tc.PFS, ID)

			// Generate server secret share 1
			_, SS1 := tc.getServerSecret(MS1[:])

			// Destroy SS1
			defer CleanMemory(SS1[:])

			// Generate server secret share 2
			_, SS2 := tc.getServerSecret(MS2[:])

			// Destroy SS2
			defer CleanMemory(SS2[:])

			// Combine server secret shares
			_, SS := tc.recombineServerSecret(SS1[:], SS2[:])

			// Destroy SS
			defer CleanMemory(SS[:])

			// Generate client secret share 1
			_, CS1 := tc.getClientSecret(MS1[:], HCID)

			// Destroy CS1
			defer CleanMemory(CS1[:])

			// Generate client secret share 2
			_, CS2 := tc.getClientSecret(MS2[:], HCID)

			// Destroy CS2
			defer CleanMemory(CS2[:])

			// Combine client secret shares
			CS := make([]byte, tc.G1S)
			_, CS = tc.recombineClientSecret(CS1[:], CS2[:])

			// Compute key-escrow less secret
			_, _, CS = tc.getKeyEscrowLessSecret(nil, 0, Z[:], CS[:])

			// Destroy CS
			defer CleanMemory(CS[:])

			// Create token
			_, TOKEN := tc.extractPin(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

			// Destroy TOKEN
			defer CleanMemory(TOKEN[:])

			// Send U, UT, V, timeValue and Message to server
			X := make([]byte, tc.PGS)
			_, _, _, V, U, _ := tc.client(HASH_TYPE_MPIN, date, ID[:], rng, X[:], PIN2, TOKEN[:], nil, nil, timeValue)

			// Destroy X
			defer CleanMemory(X[:])

			rtn, _, _, _, _, _ := tc.server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], nil, V[:], ID[:], Pa, nil, false)
			if rtn != 0 {
				t.Errorf("One-Pass failed; rtn=%v", rtn)
			}
		})
	}
}

func TestKeyEscrowLessRandom(t *testing.T) {
	for _, tc := range mPinTestCases {
		t.Run(tc.curve, func(t *testing.T) {

			// Assign the End-User an ID
			IDstr := "testUser@miracl.com"
			ID := []byte(IDstr)

			// Epoch time in days
			date := 0

			// Epoch time in seconds
			timeValue := 1439465203

			// PIN variable to create token
			PIN1 := 1234
			// PIN variable to authenticate
			PIN2 := 1234

			// Seed value for Random Number Generator (RNG)
			seedHex := "ac4509d6"
			seed, err := hex.DecodeString(seedHex)
			if err != nil {
				fmt.Println("Error decoding seed value")
				return
			}
			rng := NewRand(seed)

			// Generate Master Secret Share 1
			_, MS1 := tc.rng(rng)

			// Destroy MS1
			defer CleanMemory(MS1[:])

			// Generate Master Secret Share 2
			_, MS2 := tc.rng(rng)

			// Destroy MS2
			defer CleanMemory(MS2[:])

			// Generate Public Key
			_, Z, Pa := tc.getDVSKeyPair(rng, nil)

			// Destroy Z
			defer CleanMemory(Z[:])

			// Compute ID|Pa
			ID = append(ID, Pa...)

			// Either Client or TA calculates Hash(ID)
			HCID := HashId(HASH_TYPE_MPIN, tc.PFS, ID)

			// Generate server secret share 1
			_, SS1 := tc.getServerSecret(MS1[:])

			// Destroy SS1
			defer CleanMemory(SS1[:])

			// Generate server secret share 2
			_, SS2 := tc.getServerSecret(MS2[:])

			// Destroy SS2
			defer CleanMemory(SS2[:])

			// Combine server secret shares
			_, SS := tc.recombineServerSecret(SS1[:], SS2[:])

			// Destroy SS
			defer CleanMemory(SS[:])

			// Generate client secret share 1
			_, CS1 := tc.getClientSecret(MS1[:], HCID)

			// Destroy CS1
			defer CleanMemory(CS1[:])

			// Generate client secret share 2
			_, CS2 := tc.getClientSecret(MS2[:], HCID)

			// Destroy CS2
			defer CleanMemory(CS2[:])

			// Combine client secret shares
			CS := make([]byte, tc.G1S)
			_, CS = tc.recombineClientSecret(CS1[:], CS2[:])

			// Compute key-escrow less secret
			_, _, CS = tc.getKeyEscrowLessSecret(nil, 0, Z[:], CS[:])

			// Destroy CS
			defer CleanMemory(CS[:])

			// Create token
			_, TOKEN := tc.extractPin(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

			// Destroy TOKEN
			defer CleanMemory(TOKEN[:])

			// Send U, UT, V, timeValue and Message to server
			X := make([]byte, tc.PGS)
			_, _, _, V, U, _ := tc.client(HASH_TYPE_MPIN, date, ID[:], rng, X[:], PIN2, TOKEN[:], nil, nil, timeValue)

			// Destroy X
			defer CleanMemory(X[:])

			// Authenticate
			rtn, _, _, _, _, _ := tc.server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], nil, V[:], ID[:], Pa, nil, false)
			if rtn != 0 {
				t.Errorf("One-Pass failed; rtn=%v", rtn)
			}
		})
	}
}

func TestKeyEscrowWrongPK(t *testing.T) {
	for _, tc := range mPinTestCases {
		t.Run(tc.curve, func(t *testing.T) {
			// Assign the End-User an ID
			IDstr := "testUser@miracl.com"
			ID := []byte(IDstr)

			// Epoch time in days
			date := 16660

			// Epoch time in seconds
			timeValue := 1439465203

			// PIN variable to create token
			PIN1 := 1234
			// PIN variable to authenticate
			PIN2 := 1234

			// Seed value for Random Number Generator (RNG)
			seedHex := "ac4509d6"
			seed, err := hex.DecodeString(seedHex)
			if err != nil {
				fmt.Println("Error decoding seed value")
				return
			}
			rng := NewRand(seed)

			// Generate Master Secret Share 1
			_, MS1 := tc.rng(rng)

			// Destroy MS1
			defer CleanMemory(MS1[:])

			// Generate Master Secret Share 2
			_, MS2 := tc.rng(rng)

			// Destroy MS2
			defer CleanMemory(MS2[:])

			// Generate wrong Public Key
			_, Z, _ := tc.getDVSKeyPair(rng, nil)
			_, _, Pa := tc.getDVSKeyPair(rng, nil)

			// Destroy Z
			defer CleanMemory(Z[:])

			// Compute ID|Pa
			ID = append(ID, Pa...)

			// Either Client or TA calculates Hash(ID)
			HCID := HashId(HASH_TYPE_MPIN, tc.PFS, ID)

			// Generate server secret share 1
			_, SS1 := tc.getServerSecret(MS1[:])

			// Destroy SS1
			defer CleanMemory(SS1[:])

			// Generate server secret share 2
			_, SS2 := tc.getServerSecret(MS2[:])

			// Destroy SS2
			defer CleanMemory(SS2[:])

			// Combine server secret shares
			_, SS := tc.recombineServerSecret(SS1[:], SS2[:])

			// Destroy SS
			defer CleanMemory(SS[:])

			// Generate client secret share 1
			_, CS1 := tc.getClientSecret(MS1[:], HCID)

			// Destroy CS1
			defer CleanMemory(CS1[:])

			// Generate client secret share 2
			_, CS2 := tc.getClientSecret(MS2[:], HCID)

			// Destroy CS2
			defer CleanMemory(CS2[:])

			// Combine client secret shares
			CS := make([]byte, tc.G1S)
			_, CS = tc.recombineClientSecret(CS1[:], CS2[:])

			// Compute key-escrow less secret
			_, _, CS = tc.getKeyEscrowLessSecret(nil, 0, Z[:], CS[:])

			// Destroy CS
			defer CleanMemory(CS[:])

			// Generate time permit share 1
			_, TP1 := tc.getClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

			// Destroy TP1
			defer CleanMemory(TP1[:])

			// Generate time permit share 2
			_, TP2 := tc.getClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

			// Destroy TP2
			defer CleanMemory(TP2[:])

			// Combine time permit shares
			_, TP := tc.recombineClientSecret(TP1[:], TP2[:])

			// Destroy TP
			defer CleanMemory(TP[:])

			// Create token
			_, TOKEN := tc.extractPin(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

			// Destroy TOKEN
			defer CleanMemory(TOKEN[:])

			// Send U, UT, V, timeValue and Message to server
			X := make([]byte, tc.PGS)
			_, _, _, V, U, UT := tc.client(HASH_TYPE_MPIN, date, ID[:], rng, X[:], PIN2, TOKEN[:], TP[:], nil, timeValue)

			// Destroy X
			defer CleanMemory(X[:])

			timeValue += 10
			// Authenticate
			expected := -19
			rtn, _, _, _, _, _ := tc.server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], Pa, nil, false)
			if rtn != expected {
				t.Errorf("One-Pass - unexpected return code; rtn: %v != %v", rtn, expected)
			}
		})
	}
}

func TestKeyEscrowLessTwoPassWrongPK(t *testing.T) {
	for _, tc := range mPinTestCases {
		t.Run(tc.curve, func(t *testing.T) {
			// Assign the End-User an ID
			IDstr := "testUser@miracl.com"
			ID := []byte(IDstr)

			// Epoch time in seconds
			timeValue := 1439465203

			// PIN variable to create token
			PIN1 := 1234
			// PIN variable to authenticate
			PIN2 := 1234

			// Seed value for Random Number Generator (RNG)
			seedHex := "ac4509d6"
			seed, err := hex.DecodeString(seedHex)
			if err != nil {
				fmt.Println("Error decoding seed value")
				return
			}
			rng := NewRand(seed)

			// Generate Master Secret Share 1
			_, MS1 := tc.rng(rng)

			// Destroy MS1
			defer CleanMemory(MS1[:])

			// Generate Master Secret Share 2
			_, MS2 := tc.rng(rng)

			// Destroy MS2
			defer CleanMemory(MS2[:])

			// Generate wrong Public Key
			_, Z := tc.rng(rng)
			_, _, Pa := tc.getDVSKeyPair(rng, nil)

			// Destroy Z
			defer CleanMemory(Z[:])

			// Compute ID|Pa
			ID = append(ID, Pa...)

			// Either Client or TA calculates Hash(ID)
			HCID := HashId(HASH_TYPE_MPIN, tc.PFS, ID)

			// Generate server secret share 1
			_, SS1 := tc.getServerSecret(MS1[:])

			// Destroy SS1
			defer CleanMemory(SS1[:])

			// Generate server secret share 2
			_, SS2 := tc.getServerSecret(MS2[:])

			// Destroy SS2
			defer CleanMemory(SS2[:])

			// Combine server secret shares
			_, SS := tc.recombineServerSecret(SS1[:], SS2[:])

			// Destroy SS
			defer CleanMemory(SS[:])

			// Generate client secret share 1
			_, CS1 := tc.getClientSecret(MS1[:], HCID)

			// Destroy CS1
			defer CleanMemory(CS1[:])

			// Generate client secret share 2
			_, CS2 := tc.getClientSecret(MS2[:], HCID)

			// Destroy CS2
			defer CleanMemory(CS2[:])

			// Combine client secret shares
			CS := make([]byte, tc.G1S)
			_, CS = tc.recombineClientSecret(CS1[:], CS2[:])

			// Compute key-escrow less secret
			_, _, CS = tc.getKeyEscrowLessSecret(nil, 0, Z[:], CS[:])

			// Destroy CS
			defer CleanMemory(CS[:])

			// Create token
			_, TOKEN := tc.extractPin(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

			// Destroy TOKEN
			defer CleanMemory(TOKEN[:])

			timeValue += 10
			// Client Pass 1
			X := make([]byte, tc.PGS)
			_, XOut, SEC, U, _ := tc.clientPass1(HASH_TYPE_MPIN, 0, ID, rng, X[:], PIN2, TOKEN[:], nil)

			// Destroy XOut
			defer CleanMemory(XOut[:])
			// Destroy SEC
			defer CleanMemory(SEC[:])

			// Server Pass 1
			var HID []byte
			HID, _ = tc.serverPass1(HASH_TYPE_MPIN, 0, ID)

			_, Y := tc.rng(rng)

			// Destroy HID
			defer CleanMemory(HID[:])
			// Destroy Y
			defer CleanMemory(Y[:])

			// Client Pass 2
			_, V := tc.clientPass2(XOut[:], Y[:], SEC[:])

			// Server Pass 2
			// Send UT as V to model bad token
			expected := -19
			rtn, _, _ := tc.serverPass2(0, HID[:], nil, Pa, Y[:], SS[:], U[:], nil, V[:], false)
			if rtn != expected {
				t.Errorf("Server Pass 2 - unexpected return code; rtn: %v != %v", rtn, expected)
			}
		})
	}
}

func TestKeyEscrowLessTwoPASS(t *testing.T) {
	for _, tc := range mPinTestCases {
		t.Run(tc.curve, func(t *testing.T) {
			// Assign the End-User an ID
			IDstr := "testUser@miracl.com"
			ID := []byte(IDstr)

			// Epoch time in seconds
			timeValue := 1439465203

			// PIN variable to create token
			PIN1 := 1234
			// PIN variable to authenticate
			PIN2 := 1234

			// Seed value for Random Number Generator (RNG)
			seedHex := "ac4509d6"
			seed, err := hex.DecodeString(seedHex)
			if err != nil {
				fmt.Println("Error decoding seed value")
				return
			}
			rng := NewRand(seed)

			// Generate Master Secret Share 1
			_, MS1 := tc.rng(rng)

			// Destroy MS1
			defer CleanMemory(MS1[:])

			// Generate Master Secret Share 2
			_, MS2 := tc.rng(rng)

			// Destroy MS2
			defer CleanMemory(MS2[:])

			// Generate Public Key
			_, Z := tc.rng(rng)
			_, _, Pa := tc.getDVSKeyPair(nil, Z[:])

			// Destroy Z
			defer CleanMemory(Z[:])

			// Compute ID|Pa
			ID = append(ID, Pa...)

			// Either Client or TA calculates Hash(ID)
			HCID := HashId(HASH_TYPE_MPIN, tc.PFS, ID)

			// Generate server secret share 1
			_, SS1 := tc.getServerSecret(MS1[:])

			// Destroy SS1
			defer CleanMemory(SS1[:])

			// Generate server secret share 2
			_, SS2 := tc.getServerSecret(MS2[:])

			// Destroy SS2
			defer CleanMemory(SS2[:])

			// Combine server secret shares
			_, SS := tc.recombineServerSecret(SS1[:], SS2[:])

			// Destroy SS
			defer CleanMemory(SS[:])

			// Generate client secret share 1
			_, CS1 := tc.getClientSecret(MS1[:], HCID)

			// Destroy CS1
			defer CleanMemory(CS1[:])

			// Generate client secret share 2
			_, CS2 := tc.getClientSecret(MS2[:], HCID)

			// Destroy CS2
			defer CleanMemory(CS2[:])

			// Combine client secret shares
			CS := make([]byte, tc.G1S)
			_, CS = tc.recombineClientSecret(CS1[:], CS2[:])

			// Compute key-escrow less secret
			_, _, CS = tc.getKeyEscrowLessSecret(nil, 0, Z[:], CS[:])

			// Destroy CS
			defer CleanMemory(CS[:])

			// Create token
			_, TOKEN := tc.extractPin(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

			// Destroy TOKEN
			defer CleanMemory(TOKEN[:])

			timeValue += 10
			// Client Pass 1
			X := make([]byte, tc.PGS)
			_, XOut, SEC, U, _ := tc.clientPass1(HASH_TYPE_MPIN, 0, ID, rng, X[:], PIN2, TOKEN[:], nil)

			// Destroy XOut
			defer CleanMemory(XOut[:])
			// Destroy SEC
			defer CleanMemory(SEC[:])

			// Server Pass 1
			var HID []byte
			HID, _ = tc.serverPass1(HASH_TYPE_MPIN, 0, ID)

			_, Y := tc.rng(rng)

			// Destroy HID
			defer CleanMemory(HID[:])
			// Destroy Y
			defer CleanMemory(Y[:])

			// Client Pass 2
			_, V := tc.clientPass2(XOut[:], Y[:], SEC[:])

			// Server Pass 2
			// Send UT as V to model bad token
			rtn, _, _ := tc.serverPass2(0, HID[:], nil, Pa, Y[:], SS[:], U[:], nil, V[:], false)
			if rtn != 0 {
				t.Errorf("Server Pass 2 failed; rtn=%v", rtn)
			}
		})
	}
}

// ExampleMPinAuthentication is example for single MPin authentication
func ExampleMPinAuthentication() {
	// Seed value for Random Number Generator (RNG)
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}
	rng := NewRand(seed)

	HASH_TYPE_MPIN := SHA256

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Epoch time in days
	date := 0

	// Epoch time in seconds
	timeValue := 0

	PIN := 1234

	// Message to sign
	var MESSAGE []byte
	// MESSAGE := []byte("test sign message")

	// Generate Master Secret Share 1
	rtn, MS1 := RandomGenerate_BN254(rng)
	if rtn != 0 {
		log.Fatalf("error generating master secret share 1: %v", rtn)
	}
	fmt.Printf("Master Secret share 1: 0x%x\n", MS1[:])

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	rtn, MS2 := RandomGenerate_BN254(rng)
	if rtn != 0 {
		log.Fatalf("error generating master secret share 2: %v", rtn)
	}
	fmt.Printf("Master Secret share 2: 0x%x\n", MS2[:])

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, PFS_BN254, ID)

	// Generate server secret share 1
	rtn, SS1 := GetServerSecret_BN254(MS1[:])
	if rtn != 0 {
		log.Fatalf("error generating server secret share 1: %v", rtn)
	}
	fmt.Printf("Server Secret share 1: 0x%x\n", SS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	rtn, SS2 := GetServerSecret_BN254(MS2[:])
	if rtn != 0 {
		log.Fatalf("error generating server secret share 2: %v", rtn)
	}
	fmt.Printf("Server Secret share 2: 0x%x\n", SS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	rtn, SS := RecombineG2_BN254(SS1[:], SS2[:])
	if rtn != 0 {
		log.Fatalf("error recombining Server Secret shares: %v", rtn)
	}
	fmt.Printf("Server Secret: 0x%x\n", SS[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	rtn, CS1 := GetClientSecret_BN254(MS1[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating client secret share 1: %v", rtn)
	}
	fmt.Printf("Client Secret share 1: 0x%x\n", CS1[:])

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	rtn, CS2 := GetClientSecret_BN254(MS2[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating client secret share 1: %v", rtn)
	}
	fmt.Printf("Client Secret share 2: 0x%x\n", CS2[:])

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_BN254)
	rtn, CS = RecombineG1_BN254(CS1[:], CS2[:])
	if rtn != 0 {
		log.Fatalf("error recombining client secret shares: %v", rtn)
	}
	fmt.Printf("Client Secret: 0x%x\n", CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	rtn, TP1 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS1[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating Time Permit share 1: %v", rtn)
	}
	fmt.Printf("Time Permit share 1: 0x%x\n", TP1[:])

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	rtn, TP2 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS2[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating Time Permit share 2: %v", rtn)
	}
	fmt.Printf("Time Permit share 2: 0x%x\n", TP2[:])

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	rtn, TP := RecombineG1_BN254(TP1[:], TP2[:])
	if rtn != 0 {
		log.Fatal("error recombining Time Permit shares: %v", rtn)
	}

	// Destroy TP
	defer CleanMemory(TP[:])

	rtn, TOKEN := ExtractPIN_BN254(HASH_TYPE_MPIN, ID[:], PIN, CS[:])
	if rtn != 0 {
		log.Fatalf("error extracting pin from Client Secret: %v", rtn)
	}
	fmt.Printf("Token: 0x%x\n", TOKEN[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	//////   Client   //////

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_BN254]byte
	rtn, XOut, Y1, SEC, U, UT := Client_BN254(HASH_TYPE_MPIN, date, ID[:], rng, X[:], PIN, TOKEN[:], TP[:], MESSAGE[:], timeValue)
	if rtn != 0 {
		log.Fatalf("error client side MPin One Pass: %v", rtn)
	}
	fmt.Printf("Y1: 0x%x\n", Y1[:])
	fmt.Printf("XOut: 0x%x\n", XOut[:])
	fmt.Printf("V: 0x%x\n", SEC[:])

	// Destroy Y1
	defer CleanMemory(Y1[:])
	// Destroy XOut
	defer CleanMemory(XOut[:])
	// Destroy SEC
	defer CleanMemory(SEC[:])
	// Destroy X
	defer CleanMemory(X[:])

	//////   Server   //////
	rtn, HID, HTID, Y2, E, F := Server_BN254(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], SEC[:], ID[:], nil, MESSAGE[:], true)
	if rtn != 0 {
		// authentication failed

		// check pin error
		err := Kangaroo_BN254(E[:], F[:])
		if err != 0 {
			log.Printf("error getting the PIN error: %v", err)
		}

		log.Fatalf("error server side MPin One Pass: %v", rtn)
	}
	fmt.Printf("Y2: 0x%x\n", Y2[:])
	fmt.Printf("HID: 0x%x\n", HID[:])
	fmt.Printf("HTID: 0x%x\n", HTID[:])

	// Destroy Y2
	defer CleanMemory(Y2[:])
	// Destroy E
	defer CleanMemory(E[:])
	// Destroy F
	defer CleanMemory(F[:])

	fmt.Printf("authenticated ID: %s \n", IDstr)

	// Output:
	// Master Secret share 1: 0x1dcdc0f9112e578e86e14dc6ac9e8e3656c9783a6275ae5df1fdd7a7156051dc
	// Master Secret share 2: 0x23f0b9b1afd4cae56af8331ed1225626bef35a012a65fe23ac819e45b6e2d4c2
	// Server Secret share 1: 0x18ed9d30343cc6381f1f361c72baeace9e601ca6a9479c3ff6797f792cf4634507ee4e81c62a515117076393961c74f22aa7a4df90775fa8aa513f568a6f18930d994d472ee81c8ea7cf2e9d700f9182e8c6ddb261c3ae2b77178c3f6783cdf80024e98b4f2f8e8a2ed8e6b9be3969f75a14d7b31ae1898ca5d3dc28e5f24163
	// Server Secret share 2: 0x07213b6c6210515a47d4aa70c2c5d7eaee11b00d2de329e39358e0f23b9237ee04017accdf6142d75943904f5623e3182e346d6d80e239403f0c0b6f44314c901545d04c0094eb123260a6ad17f4642de2753e4cb6962b5125c0c74636fe4f5f0728033b81a71cac68188f99b5e1b5e1f9d738aea040c91a7eafbde077596963
	// Server Secret: 0x0bc6d400159987574bf3618bd1f12640b1c4f82eb6119f6df16cb03010712088116cac4fb8b22917cd4c6a08433a55ddd4c3d4a4740cefca4ad5f15512793bbb08106f573aa4ce822ca361def6ca2f56da5fb2f3e4e4ab24f223dc25b11c4e9521328c5d3bec565b75d8cf6423867c8683182ea69845cd7079824ba7c64fae7f
	// Client Secret share 1: 0x041e210253763ab1dd23d7d0cf35d1ff88233fa5dd2b9ca59893c3743d8698c7a2211cb5670784f8f08bbffdabb8ee4834852414a48819b0bd226abdb50620f44a
	// Client Secret share 2: 0x0405ca872a20e803194126e282a2fb45a7b37cdfc40515a6045a7c3beb2bac29bb1b7462cd085de349e8ad1727814f735d8413a9d56b524b148d27e10d02c3f660
	// Client Secret: 0x04162e9f1048095fb44d549b7c9ef0f36662da47c93364f72f9f41a6c3361cd3a90770d92a46876f9e73cdce6609cdc7139cd22cd2908d2fc6a3ff20ece93c5750
	// Time Permit share 1: 0x0404c171f581824179675af09d9ef22dd9c50ca3a60270baaf8b906c3803ede9d10e88485278e55dab465b6289792fe3f66729cfe42820562095e1972315a6c1cd
	// Time Permit share 2: 0x0419226c66ebd7cefb7b6169c0762dbaa1d971a66a49837bc791be893282432e47151f25c931c03c82c563ee672f2210b4f7df9d3874c781ec18d8011f3db9009e
	// Token: 0x040bad25790c12811cbe7c5bc767540310e7a302f8ebb4bec5742bad961c3eb5c9023c4b41d16febccd9e5f66773beb93e9bbd6b640aba569bb2f07f0a143103e9
	// Y1: 0x03170d0f29c7cc85e659fecb070536cd92811a2b5a0edd3abe64d3c822997e1c
	// XOut: 0x2497b956d9193d707326c4fc7364744f7863d020efc2d2f8a86a864691e103d4
	// V: 0x041aa6455c08c8324de05599b358538fd05ddbe9306c1d27c2d2e5e20a663839750eb244633ebaea6705b960ccbeb30dd68b0b58794df4a8229e349070a1ce6356
	// Y2: 0x03170d0f29c7cc85e659fecb070536cd92811a2b5a0edd3abe64d3c822997e1c
	// HID: 0x04144527fe508041db5eef90538f2547c4bd817d6dc94f67c7226585ec67706b0301a15ec8bff704176dab6371eae41ccc07a9c9b76e4be8162c56cb115e64024a
	// HTID: 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	// authenticated ID: testUser@miracl.com

}

// ExampleMPinAuthentications is example for concurrent MPin authentications
// TODO: Convert to test or benchmark
func ExampleMPinAuthentications() {
	numRoutines := 1000

	// Seed value for Random Number Generator (RNG)
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}
	rng := NewRand(seed)

	wg := sync.WaitGroup{}

	wg.Add(numRoutines)
	for x := 0; x < numRoutines; x++ {
		go func(rng *Rand, wg *sync.WaitGroup) {
			HASH_TYPE_MPIN := SHA256

			// Assign the End-User an ID
			IDstr := "testUser@miracl.com"
			ID := []byte(IDstr)

			// Epoch time in days
			date := Today()

			// Epoch time in seconds
			timeValue := GetTime()

			// PIN variable to create token
			PIN := 1234

			// Message to sign
			MESSAGE := []byte("test sign message")

			// Generate Master Secret Share 1
			rtn, MS1 := RandomGenerate_BN254(rng)
			if rtn != 0 {
				log.Fatalf("error generating master secret share 1: %v", rtn)
			}
			// Destroy MS1
			defer CleanMemory(MS1[:])

			// Generate Master Secret Share 2
			rtn, MS2 := RandomGenerate_BN254(rng)
			if rtn != 0 {
				log.Fatalf("error generating master secret share 2: %v", rtn)
			}
			// Destroy MS2
			defer CleanMemory(MS2[:])

			// Either Client or TA calculates Hash(ID)
			HCID := HashId(HASH_TYPE_MPIN, PFS_BN254, ID)

			// Generate server secret share 1
			rtn, SS1 := GetServerSecret_BN254(MS1[:])
			if rtn != 0 {
				log.Fatalf("error generating server secret share 1: %v", rtn)
			}
			// Destroy SS1
			defer CleanMemory(SS1[:])

			// Generate server secret share 2
			rtn, SS2 := GetServerSecret_BN254(MS2[:])
			if rtn != 0 {
				log.Fatalf("error generating server secret share 2: %v", rtn)
			}
			// Destroy SS2
			defer CleanMemory(SS2[:])

			// Combine server secret shares
			rtn, SS := RecombineG2_BN254(SS1[:], SS2[:])
			if rtn != 0 {
				log.Fatalf("error recombining server secret shares: %v", rtn)
			}
			// Destroy SS
			defer CleanMemory(SS[:])

			// Generate client secret share 1
			rtn, CS1 := GetClientSecret_BN254(MS1[:], HCID)
			if rtn != 0 {
				log.Fatalf("error generating client secret share 1: %v", rtn)
			}
			// Destroy CS1
			defer CleanMemory(CS1[:])

			// Generate client secret share 2
			rtn, CS2 := GetClientSecret_BN254(MS2[:], HCID)
			if rtn != 0 {
				log.Fatalf("error generating client secret share 2: %v", rtn)
			}
			// Destroy CS2
			defer CleanMemory(CS2[:])

			// Combine client secret shares
			CS := make([]byte, G1S_BN254)
			rtn, CS = RecombineG1_BN254(CS1[:], CS2[:])
			if rtn != 0 {
				log.Fatalf("error recombining client secret shares: %v", rtn)
			}
			// Destroy CS
			defer CleanMemory(CS[:])

			// Generate time permit share 1
			rtn, TP1 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS1[:], HCID)
			if rtn != 0 {
				log.Fatalf("error generating time permit share 1: %v", rtn)
			}
			// Destroy TP1
			defer CleanMemory(TP1[:])

			// Generate time permit share 2
			rtn, TP2 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS2[:], HCID)
			if rtn != 0 {
				log.Fatalf("error generating time permit share 2: %v", rtn)
			}
			// Destroy TP2
			defer CleanMemory(TP2[:])

			// Combine time permit shares
			rtn, TP := RecombineG1_BN254(TP1[:], TP2[:])
			if rtn != 0 {
				log.Fatalf("error recombining time permit shares: %v", rtn)
			}
			// Destroy TP
			defer CleanMemory(TP[:])

			rtn, TOKEN := ExtractPIN_BN254(HASH_TYPE_MPIN, ID[:], PIN, CS[:])
			if rtn != 0 {
				log.Fatalf("error extracting pin from client secret: %v", rtn)
			}
			// Destroy TOKEN
			defer CleanMemory(TOKEN[:])

			// --- Client ---
			// Send U, UT, V, timeValue and Message to server
			var X [PGS_BN254]byte
			rtn, _, _, SEC, U, UT := Client_BN254(HASH_TYPE_MPIN, date, ID[:], rng, X[:], PIN, TOKEN[:], TP[:], MESSAGE[:], timeValue)
			if rtn != 0 {
				log.Fatalf("error client side MPin One Pass: %v", rtn)
			}

			// --- Server ---
			rtn, _, _, _, E, F := Server_BN254(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], SEC[:], ID[:], nil, MESSAGE[:], true)
			if rtn != 0 {
				// authentication failed

				// check pin error
				err := Kangaroo_BN254(E[:], F[:])
				if err != 0 {
					log.Printf("error getting the PIN error: %v", err)
				}

				log.Fatalf("error server side MPin One Pass: %v", rtn)
			}

			wg.Done()
		}(rng, &wg)
	}
	wg.Wait()

	fmt.Printf("Done")

	// Output: Done
}

// ExampleMPinFull is example for MPin full work-flow
func ExampleMPinFull() {
	HASH_TYPE_MPIN := SHA256

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Epoch time in days
	date := 0

	// Epoch time in seconds
	timeValue := 0

	PIN := 1234

	// Seed value for Random Number Generator (RNG)
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}
	rng := NewRand(seed)

	// Message to sign
	var MESSAGE []byte
	// MESSAGE := []byte("test sign message")

	// Generate Master Secret Share 1
	rtn, MS1 := RandomGenerate_BN254(rng)
	if rtn != 0 {
		log.Fatalf("error generating master secret share 1: %v", rtn)
	}
	fmt.Printf("Master Secret share 1: 0x%x\n", MS1[:])

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	rtn, MS2 := RandomGenerate_BN254(rng)
	if rtn != 0 {
		log.Fatalf("error generating master secret share 2: %v", rtn)
	}
	fmt.Printf("Master Secret share 2: 0x%x\n", MS2[:])

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, PFS_BN254, ID)

	// Generate server secret share 1
	rtn, SS1 := GetServerSecret_BN254(MS1[:])
	if rtn != 0 {
		log.Fatalf("error generating server secret share 1: %v", rtn)
	}
	fmt.Printf("Server Secret share 1: 0x%x\n", SS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	rtn, SS2 := GetServerSecret_BN254(MS2[:])
	if rtn != 0 {
		log.Fatalf("error generating server secret share 2: %v", rtn)
	}
	fmt.Printf("Server Secret share 2: 0x%x\n", SS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	rtn, SS := RecombineG2_BN254(SS1[:], SS2[:])
	if rtn != 0 {
		log.Fatalf("error recombining Server Secret shares: %v", rtn)
	}
	fmt.Printf("Server Secret: 0x%x\n", SS[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	rtn, CS1 := GetClientSecret_BN254(MS1[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating client secret share 1: %v", rtn)
	}
	fmt.Printf("Client Secret share 1: 0x%x\n", CS1[:])

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	rtn, CS2 := GetClientSecret_BN254(MS2[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating client secret share 1: %v", rtn)
	}
	fmt.Printf("Client Secret share 2: 0x%x\n", CS2[:])

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_BN254)
	rtn, CS = RecombineG1_BN254(CS1[:], CS2[:])
	if rtn != 0 {
		log.Fatalf("error recombining client secret shares: %v", rtn)
	}
	fmt.Printf("Client Secret: 0x%x\n", CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	rtn, TOKEN := ExtractPIN_BN254(HASH_TYPE_MPIN, ID[:], PIN, CS[:])
	if rtn != 0 {
		log.Fatalf("error extracting pin from Client Secret: %v", rtn)
	}
	fmt.Printf("Token: 0x%x\n", TOKEN[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	//////   Client   //////

	// Precomputation
	rtn, G1, G2 := Precompute_BN254(TOKEN[:], HCID)
	if rtn != 0 {
		log.Fatalf("error client side MPin Full precompute: %v", rtn)
	}

	// Destroy G2
	defer CleanMemory(G2[:])
	// Destroy G1
	defer CleanMemory(G1[:])

	// Send U, V, timeValue and Message to server
	var X [PGS_BN254]byte
	rtn, XOut, Y1, V, U, _ := Client_BN254(HASH_TYPE_MPIN, date, ID[:], rng, X[:], PIN, TOKEN[:], nil, MESSAGE[:], timeValue)
	if rtn != 0 {
		log.Fatalf("error client side MPin Full: %v", rtn)
	}
	fmt.Printf("Y1: 0x%x\n", Y1[:])
	fmt.Printf("XOut: 0x%x\n", XOut[:])

	// Destroy Y1
	defer CleanMemory(Y1[:])
	// Destroy XOut
	defer CleanMemory(XOut[:])
	// Destroy V
	defer CleanMemory(V[:])

	// Send Z=r.ID to Server
	var R [PGS_BN254]byte
	rtn, ROut, Z := GetG1Multiple_BN254(rng, 1, R[:], HCID[:])
	fmt.Printf("ROut: 0x%x\n", ROut[:])

	// Destroy R
	defer CleanMemory(R[:])
	// Destroy ROut
	defer CleanMemory(ROut[:])
	// Destroy Z
	defer CleanMemory(Z[:])

	//////   Server   //////
	rtn, HID, _, Y2, E, F := Server_BN254(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], nil, V[:], ID[:], nil, MESSAGE[:], true)
	if rtn != 0 {
		// authentication failed

		// check pin error
		err := Kangaroo_BN254(E[:], F[:])
		if err != 0 {
			log.Printf("error getting the PIN error: %v", err)
		}

		log.Fatalf("error server side MPin One Pass: %v", rtn)
	}
	fmt.Printf("Y2: 0x%x\n", Y2[:])
	fmt.Printf("HID: 0x%x\n", HID[:])

	// Destroy Y2
	defer CleanMemory(Y2[:])
	// Destroy E
	defer CleanMemory(E[:])
	// Destroy F
	defer CleanMemory(F[:])

	// send T=w.ID to client
	var W [PGS_BN254]byte
	rtn, WOut, T := GetG1Multiple_BN254(rng, 0, W[:], HID[:])
	fmt.Printf("WOut: 0x%x\n", WOut[:])
	fmt.Printf("T: 0x%x\n", T[:])

	// Destroy W
	defer CleanMemory(W[:])
	// Destroy WOut
	defer CleanMemory(WOut[:])
	// Destroy T
	defer CleanMemory(T[:])

	// Hash all values
	HM := HashAll(HASH_TYPE_MPIN, PFS_BN254, HCID[:], U[:], nil, V[:], Y2[:], Z[:], T[:])

	// Destroy HM
	defer CleanMemory(HM[:])

	rtn, AES_KEY_SERVER := ServerKey_BN254(HASH_TYPE_MPIN, Z[:], SS[:], WOut[:], HM[:], HID[:], U[:], nil)
	if rtn != 0 {
		log.Fatalf("error generating AES server key: %v", rtn)
	}
	fmt.Printf("server AES Key =  %x\n", AES_KEY_SERVER[:])

	// Destroy AES_KEY_SERVER
	defer CleanMemory(AES_KEY_SERVER[:])

	rtn, AES_KEY_CLIENT := ClientKey_BN254(HASH_TYPE_MPIN, PIN, G1[:], G2[:], ROut[:], XOut[:], HM[:], T[:])
	if rtn != 0 {
		log.Fatalf("error generating AES client key: %v", rtn)
	}
	fmt.Printf("client AES key =  0x%x\n", AES_KEY_CLIENT[:])

	// Destroy AES_KEY_CLIENT
	defer CleanMemory(AES_KEY_CLIENT[:])

	//////   Server   //////

	// Initialization vector
	IV := GenerateRandomByte(rng, 12)
	fmt.Printf("IV: 0x%x\n", IV[:])

	// Destroy IV
	defer CleanMemory(IV[:])

	// header
	HEADER := GenerateRandomByte(rng, 16)
	fmt.Printf("Header: 0x%x\n", HEADER[:])

	// Destroy HEADER
	defer CleanMemory(HEADER[:])

	// Input plaintext
	plaintextStr := "A test message"
	PLAINTEXT1 := []byte(plaintextStr)

	// Destroy PLAINTEXT1
	defer CleanMemory(PLAINTEXT1[:])

	// AES-GCM Encryption
	CIPHERTEXT, TAG1, err := AesGcmEncrypt(AES_KEY_SERVER[:], IV[:], HEADER[:], PLAINTEXT1[:])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ciphertext: 0x%x\n", CIPHERTEXT[:])
	fmt.Printf("tag: 0x%x\n", TAG1[:])

	// Destroy CIPHERTEXT
	defer CleanMemory(CIPHERTEXT[:])
	// Destroy TAG1
	defer CleanMemory(TAG1[:])

	// Send IV, HEADER, CIPHERTEXT and TAG1 to client

	// AES-GCM Decryption
	PLAINTEXT2, TAG2, err := AesGcmDecrypt(AES_KEY_CLIENT[:], IV[:], HEADER[:], CIPHERTEXT[:])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("plaintext:  0x%x\n", PLAINTEXT2[:])
	fmt.Printf("tag:  0x%x\n", TAG2[:])
	fmt.Printf("decrypted string: %s \n", string(PLAINTEXT2))

	// Destroy PLAINTEXT2
	defer CleanMemory(PLAINTEXT2[:])
	// Destroy TAG2
	defer CleanMemory(TAG2[:])

	// Output:
	// Master Secret share 1: 0x1dcdc0f9112e578e86e14dc6ac9e8e3656c9783a6275ae5df1fdd7a7156051dc
	// Master Secret share 2: 0x23f0b9b1afd4cae56af8331ed1225626bef35a012a65fe23ac819e45b6e2d4c2
	// Server Secret share 1: 0x18ed9d30343cc6381f1f361c72baeace9e601ca6a9479c3ff6797f792cf4634507ee4e81c62a515117076393961c74f22aa7a4df90775fa8aa513f568a6f18930d994d472ee81c8ea7cf2e9d700f9182e8c6ddb261c3ae2b77178c3f6783cdf80024e98b4f2f8e8a2ed8e6b9be3969f75a14d7b31ae1898ca5d3dc28e5f24163
	// Server Secret share 2: 0x07213b6c6210515a47d4aa70c2c5d7eaee11b00d2de329e39358e0f23b9237ee04017accdf6142d75943904f5623e3182e346d6d80e239403f0c0b6f44314c901545d04c0094eb123260a6ad17f4642de2753e4cb6962b5125c0c74636fe4f5f0728033b81a71cac68188f99b5e1b5e1f9d738aea040c91a7eafbde077596963
	// Server Secret: 0x0bc6d400159987574bf3618bd1f12640b1c4f82eb6119f6df16cb03010712088116cac4fb8b22917cd4c6a08433a55ddd4c3d4a4740cefca4ad5f15512793bbb08106f573aa4ce822ca361def6ca2f56da5fb2f3e4e4ab24f223dc25b11c4e9521328c5d3bec565b75d8cf6423867c8683182ea69845cd7079824ba7c64fae7f
	// Client Secret share 1: 0x041e210253763ab1dd23d7d0cf35d1ff88233fa5dd2b9ca59893c3743d8698c7a2211cb5670784f8f08bbffdabb8ee4834852414a48819b0bd226abdb50620f44a
	// Client Secret share 2: 0x0405ca872a20e803194126e282a2fb45a7b37cdfc40515a6045a7c3beb2bac29bb1b7462cd085de349e8ad1727814f735d8413a9d56b524b148d27e10d02c3f660
	// Client Secret: 0x04162e9f1048095fb44d549b7c9ef0f36662da47c93364f72f9f41a6c3361cd3a90770d92a46876f9e73cdce6609cdc7139cd22cd2908d2fc6a3ff20ece93c5750
	// Token: 0x040bad25790c12811cbe7c5bc767540310e7a302f8ebb4bec5742bad961c3eb5c9023c4b41d16febccd9e5f66773beb93e9bbd6b640aba569bb2f07f0a143103e9
	// Y1: 0x03170d0f29c7cc85e659fecb070536cd92811a2b5a0edd3abe64d3c822997e1c
	// XOut: 0x2497b956d9193d707326c4fc7364744f7863d020efc2d2f8a86a864691e103d4
	// ROut: 0x01c3545c4e07fe2cafcbc16ac110cc783fb17bdb03f2bca57a51be6fbefedc99
	// Y2: 0x03170d0f29c7cc85e659fecb070536cd92811a2b5a0edd3abe64d3c822997e1c
	// HID: 0x04144527fe508041db5eef90538f2547c4bd817d6dc94f67c7226585ec67706b0301a15ec8bff704176dab6371eae41ccc07a9c9b76e4be8162c56cb115e64024a
	// WOut: 0x0170e0126f019d1a452419d3c9fc9b7eb72753e72a3f8a3b3f696aaf6fd0c815
	// T: 0x0410cdc58ee5d8040a1cacacae65fa5fb4594786a62886d0da72655fbd587532900377a447757a21df6c5f370f16ffb44679ccd14c3936740c7283d0bf0751ee08
	// server AES Key =  2a910ff0c7cc6ccabd92311500fb8d9b
	// client AES key =  0x2a910ff0c7cc6ccabd92311500fb8d9b
	// IV: 0x8003b44d9ddb5a5fd69b0695
	// Header: 0xfd7348ef51707cf7ce74959aa5f12979
	// ciphertext: 0x5f5b7561c0feb466ea5742dcc5e6
	// tag: 0x644e1db0dd92bc63979959943572acd3
	// plaintext:  0x412074657374206d657373616765
	// tag:  0x644e1db0dd92bc63979959943572acd3
	// decrypted string: A test message
}

// ExampleMPinFullWithTP is example for MPin full work-flow with time permits
func ExampleMPinFullWithTP() {
	HASH_TYPE_MPIN := SHA256

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Epoch time in days
	// TODO: Check why doesn't work with 0
	date := 1

	// Epoch time in seconds
	timeValue := 0

	PIN := 1234

	// Seed value for Random Number Generator (RNG)
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}
	rng := NewRand(seed)

	// Message to sign
	var MESSAGE []byte
	// MESSAGE := []byte("test sign message")

	// Generate Master Secret Share 1
	rtn, MS1 := RandomGenerate_BN254(rng)
	if rtn != 0 {
		log.Fatalf("error generating master secret share 1: %v", rtn)
	}
	fmt.Printf("Master Secret share 1: 0x%x\n", MS1[:])

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	rtn, MS2 := RandomGenerate_BN254(rng)
	if rtn != 0 {
		log.Fatalf("error generating master secret share 2: %v", rtn)
	}
	fmt.Printf("Master Secret share 2: 0x%x\n", MS2[:])

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, PFS_BN254, ID)

	// Generate server secret share 1
	rtn, SS1 := GetServerSecret_BN254(MS1[:])
	if rtn != 0 {
		log.Fatalf("error generating server secret share 1: %v", rtn)
	}
	fmt.Printf("Server Secret share 1: 0x%x\n", SS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	rtn, SS2 := GetServerSecret_BN254(MS2[:])
	if rtn != 0 {
		log.Fatalf("error generating server secret share 2: %v", rtn)
	}
	fmt.Printf("Server Secret share 2: 0x%x\n", SS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	rtn, SS := RecombineG2_BN254(SS1[:], SS2[:])
	if rtn != 0 {
		log.Fatalf("error recombining Server Secret shares: %v", rtn)
	}
	fmt.Printf("Server Secret: 0x%x\n", SS[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	rtn, CS1 := GetClientSecret_BN254(MS1[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating client secret share 1: %v", rtn)
	}
	fmt.Printf("Client Secret share 1: 0x%x\n", CS1[:])

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	rtn, CS2 := GetClientSecret_BN254(MS2[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating client secret share 1: %v", rtn)
	}
	fmt.Printf("Client Secret share 2: 0x%x\n", CS2[:])

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_BN254)
	rtn, CS = RecombineG1_BN254(CS1[:], CS2[:])
	if rtn != 0 {
		log.Fatalf("error recombining client secret shares: %v", rtn)
	}
	fmt.Printf("Client Secret: 0x%x\n", CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	rtn, TP1 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS1[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating Time Permit share 1: %v", rtn)
	}
	fmt.Printf("Time Permit share 1: 0x%x\n", TP1[:])

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	rtn, TP2 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS2[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating Time Permit share 2: %v", rtn)
	}
	fmt.Printf("Time Permit share 2: 0x%x\n", TP2[:])

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	rtn, TP := RecombineG1_BN254(TP1[:], TP2[:])
	if rtn != 0 {
		log.Fatalf("error recombining Time Permit shares: %v", rtn)
	}

	// Destroy TP
	defer CleanMemory(TP[:])

	rtn, TOKEN := ExtractPIN_BN254(HASH_TYPE_MPIN, ID[:], PIN, CS[:])
	if rtn != 0 {
		log.Fatalf("error extracting pin from Client Secret: %v", rtn)
	}
	fmt.Printf("Token: 0x%x\n", TOKEN[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	//////   Client   //////

	// Precomputation
	rtn, G1, G2 := Precompute_BN254(TOKEN[:], HCID)
	if rtn != 0 {
		log.Fatalf("error client side MPin Full precompute: %v", rtn)
	}

	// Destroy G2
	defer CleanMemory(G2[:])
	// Destroy G1
	defer CleanMemory(G1[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_BN254]byte
	rtn, XOut, Y1, V, U, UT := Client_BN254(HASH_TYPE_MPIN, date, ID[:], rng, X[:], PIN, TOKEN[:], TP[:], MESSAGE[:], timeValue)
	if rtn != 0 {
		log.Fatalf("error client side MPin Full: %v", rtn)
	}
	fmt.Printf("Y1: 0x%x\n", Y1[:])
	fmt.Printf("XOut: 0x%x\n", XOut[:])

	// Destroy Y1
	defer CleanMemory(Y1[:])
	// Destroy XOut
	defer CleanMemory(XOut[:])
	// Destroy V
	defer CleanMemory(V[:])

	// Send Z=r.ID to Server
	var R [PGS_BN254]byte
	rtn, ROut, Z := GetG1Multiple_BN254(rng, 1, R[:], HCID[:])
	fmt.Printf("ROut: 0x%x\n", ROut[:])

	// Destroy R
	defer CleanMemory(R[:])
	// Destroy ROut
	defer CleanMemory(ROut[:])
	// Destroy Z
	defer CleanMemory(Z[:])

	//////   Server   //////
	rtn, HID, HTID, Y2, E, F := Server_BN254(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], nil, MESSAGE[:], true)
	if rtn != 0 {
		// authentication failed

		// check pin error
		err := Kangaroo_BN254(E[:], F[:])
		if err != 0 {
			log.Printf("error getting the PIN error: %v", err)
		}

		log.Fatalf("error server side MPin One Pass: %v", rtn)
	}
	fmt.Printf("Y2: 0x%x\n", Y2[:])
	fmt.Printf("HID: 0x%x\n", HID[:])
	fmt.Printf("HTID: 0x%x\n", HTID[:])

	// Destroy Y2
	defer CleanMemory(Y2[:])
	// Destroy E
	defer CleanMemory(E[:])
	// Destroy F
	defer CleanMemory(F[:])

	// send T=w.ID to client
	var W [PGS_BN254]byte
	rtn, WOut, T := GetG1Multiple_BN254(rng, 0, W[:], HTID[:])
	fmt.Printf("WOut: 0x%x\n", WOut[:])
	fmt.Printf("T: 0x%x\n", T[:])

	// Destroy W
	defer CleanMemory(W[:])
	// Destroy WOut
	defer CleanMemory(WOut[:])
	// Destroy T
	defer CleanMemory(T[:])

	// Hash all values
	HM := HashAll(HASH_TYPE_MPIN, PFS_BN254, HCID[:], U[:], UT[:], V[:], Y2[:], Z[:], T[:])

	// Destroy HM
	defer CleanMemory(HM[:])

	rtn, AES_KEY_SERVER := ServerKey_BN254(HASH_TYPE_MPIN, Z[:], SS[:], WOut[:], HM[:], HID[:], U[:], UT[:])
	if rtn != 0 {
		log.Fatalf("error generating AES server key: %v", rtn)
	}
	fmt.Printf("server AES Key =  %x\n", AES_KEY_SERVER[:])

	// Destroy AES_KEY_SERVER
	defer CleanMemory(AES_KEY_SERVER[:])

	rtn, AES_KEY_CLIENT := ClientKey_BN254(HASH_TYPE_MPIN, PIN, G1[:], G2[:], ROut[:], XOut[:], HM[:], T[:])
	if rtn != 0 {
		log.Fatalf("error generating AES client key: %v", rtn)
	}
	fmt.Printf("client AES key =  0x%x\n", AES_KEY_CLIENT[:])

	// Destroy AES_KEY_CLIENT
	defer CleanMemory(AES_KEY_CLIENT[:])

	//////   Server   //////

	// Initialization vector
	IV := GenerateRandomByte(rng, 12)
	fmt.Printf("IV: 0x%x\n", IV[:])

	// Destroy IV
	defer CleanMemory(IV[:])

	// header
	HEADER := GenerateRandomByte(rng, 16)
	fmt.Printf("Header: 0x%x\n", HEADER[:])

	// Destroy HEADER
	defer CleanMemory(HEADER[:])

	// Input plaintext
	plaintextStr := "A test message"
	PLAINTEXT1 := []byte(plaintextStr)

	// Destroy PLAINTEXT1
	defer CleanMemory(PLAINTEXT1[:])

	// AES-GCM Encryption
	CIPHERTEXT, TAG1, err := AesGcmEncrypt(AES_KEY_SERVER[:], IV[:], HEADER[:], PLAINTEXT1[:])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ciphertext: 0x%x\n", CIPHERTEXT[:])
	fmt.Printf("tag: 0x%x\n", TAG1[:])

	// Destroy CIPHERTEXT
	defer CleanMemory(CIPHERTEXT[:])
	// Destroy TAG1
	defer CleanMemory(TAG1[:])

	// Send IV, HEADER, CIPHERTEXT and TAG1 to client

	// AES-GCM Decryption
	PLAINTEXT2, TAG2, err := AesGcmDecrypt(AES_KEY_CLIENT[:], IV[:], HEADER[:], CIPHERTEXT[:])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("plaintext:  0x%x\n", PLAINTEXT2[:])
	fmt.Printf("tag:  0x%x\n", TAG2[:])
	fmt.Printf("decrypted string: %s \n", string(PLAINTEXT2))

	// Destroy PLAINTEXT2
	defer CleanMemory(PLAINTEXT2[:])
	// Destroy TAG2
	defer CleanMemory(TAG2[:])

	// Output:
	// Master Secret share 1: 0x1dcdc0f9112e578e86e14dc6ac9e8e3656c9783a6275ae5df1fdd7a7156051dc
	// Master Secret share 2: 0x23f0b9b1afd4cae56af8331ed1225626bef35a012a65fe23ac819e45b6e2d4c2
	// Server Secret share 1: 0x18ed9d30343cc6381f1f361c72baeace9e601ca6a9479c3ff6797f792cf4634507ee4e81c62a515117076393961c74f22aa7a4df90775fa8aa513f568a6f18930d994d472ee81c8ea7cf2e9d700f9182e8c6ddb261c3ae2b77178c3f6783cdf80024e98b4f2f8e8a2ed8e6b9be3969f75a14d7b31ae1898ca5d3dc28e5f24163
	// Server Secret share 2: 0x07213b6c6210515a47d4aa70c2c5d7eaee11b00d2de329e39358e0f23b9237ee04017accdf6142d75943904f5623e3182e346d6d80e239403f0c0b6f44314c901545d04c0094eb123260a6ad17f4642de2753e4cb6962b5125c0c74636fe4f5f0728033b81a71cac68188f99b5e1b5e1f9d738aea040c91a7eafbde077596963
	// Server Secret: 0x0bc6d400159987574bf3618bd1f12640b1c4f82eb6119f6df16cb03010712088116cac4fb8b22917cd4c6a08433a55ddd4c3d4a4740cefca4ad5f15512793bbb08106f573aa4ce822ca361def6ca2f56da5fb2f3e4e4ab24f223dc25b11c4e9521328c5d3bec565b75d8cf6423867c8683182ea69845cd7079824ba7c64fae7f
	// Client Secret share 1: 0x041e210253763ab1dd23d7d0cf35d1ff88233fa5dd2b9ca59893c3743d8698c7a2211cb5670784f8f08bbffdabb8ee4834852414a48819b0bd226abdb50620f44a
	// Client Secret share 2: 0x0405ca872a20e803194126e282a2fb45a7b37cdfc40515a6045a7c3beb2bac29bb1b7462cd085de349e8ad1727814f735d8413a9d56b524b148d27e10d02c3f660
	// Client Secret: 0x04162e9f1048095fb44d549b7c9ef0f36662da47c93364f72f9f41a6c3361cd3a90770d92a46876f9e73cdce6609cdc7139cd22cd2908d2fc6a3ff20ece93c5750
	// Time Permit share 1: 0x04175183f6648f0c6bbfc46fc72484542a1ffebde9ceb18bfb6f440e9e63c03a1f20113fde1c57831699985f9347f77f9465d0ffc5734d2052051429868c976dbb
	// Time Permit share 2: 0x041ef32c444874db6327f66af34494d8721f730f8788ba975886c1404ac5e957b321489a4d5069153048be9dcf5d3305f2019c62a1bc87e9f360deb7275a6b01da
	// Token: 0x040bad25790c12811cbe7c5bc767540310e7a302f8ebb4bec5742bad961c3eb5c9023c4b41d16febccd9e5f66773beb93e9bbd6b640aba569bb2f07f0a143103e9
	// Y1: 0x08ac6a08148b488925935fb8e9ab6180d7262a196a17090774724332a46be86a
	// XOut: 0x2497b956d9193d707326c4fc7364744f7863d020efc2d2f8a86a864691e103d4
	// ROut: 0x01c3545c4e07fe2cafcbc16ac110cc783fb17bdb03f2bca57a51be6fbefedc99
	// Y2: 0x08ac6a08148b488925935fb8e9ab6180d7262a196a17090774724332a46be86a
	// HID: 0x04144527fe508041db5eef90538f2547c4bd817d6dc94f67c7226585ec67706b0301a15ec8bff704176dab6371eae41ccc07a9c9b76e4be8162c56cb115e64024a
	// HTID: 0x04097dc00fe9db8d394c2c8a883ce1fc09e3f701f4ce93771b3094bc594d9a26e320a6f220ef2d42b7ff326e45024e33b5d0bc3ce5f41ebf01ef7f999a124d54d3
	// WOut: 0x0170e0126f019d1a452419d3c9fc9b7eb72753e72a3f8a3b3f696aaf6fd0c815
	// T: 0x04114fb1a3a8a9ab83066e9e2430c1b41a6c7661ef5851ef3ae538c34903f937340c15a77039e60518cab235cf816451dfd1d5769fd72ed3c41d74f5a1f978a9dd
	// server AES Key =  18bdd2141debeed19954583471b9b065
	// client AES key =  0x18bdd2141debeed19954583471b9b065
	// IV: 0x8003b44d9ddb5a5fd69b0695
	// Header: 0xfd7348ef51707cf7ce74959aa5f12979
	// ciphertext: 0xfc5b2310aa4fe985d66d37fe91f3
	// tag: 0x55449a13b08880f33b4983e4b8b6aaea
	// plaintext:  0x412074657374206d657373616765
	// tag:  0x55449a13b08880f33b4983e4b8b6aaea
	// decrypted string: A test message
}

// ExampleMPinTwoPass is example for MPin two pass
func ExampleMPinTwoPass() {
	HASH_TYPE_MPIN := SHA256

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Epoch time in days
	date := 0

	PIN := 1234

	// Seed value for Random Number Generator
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}
	rng := NewRand(seed)

	// Generate Master Secret Share 1
	rtn, MS1 := RandomGenerate_BN254(rng)
	if rtn != 0 {
		log.Fatalf("error generating master secret share 1: %v", rtn)
	}
	fmt.Printf("Master Secret share 1: 0x%x\n", MS1[:])

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	rtn, MS2 := RandomGenerate_BN254(rng)
	if rtn != 0 {
		log.Fatalf("error generating master secret share 2: %v", rtn)
	}
	fmt.Printf("Master Secret share 2: 0x%x\n", MS2[:])

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, PFS_BN254, ID)

	// Generate server secret share 1
	rtn, SS1 := GetServerSecret_BN254(MS1[:])
	if rtn != 0 {
		log.Fatalf("error generating server secret share 1: %v", rtn)
	}
	fmt.Printf("Server Secret share 1: 0x%x\n", SS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	rtn, SS2 := GetServerSecret_BN254(MS2[:])
	if rtn != 0 {
		log.Fatalf("error generating server secret share 2: %v", rtn)
	}
	fmt.Printf("Server Secret share 2: 0x%x\n", SS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	rtn, SS := RecombineG2_BN254(SS1[:], SS2[:])
	if rtn != 0 {
		log.Fatalf("error recombining Server Secret shares: %v", rtn)
	}
	fmt.Printf("Server Secret: 0x%x\n", SS[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	rtn, CS1 := GetClientSecret_BN254(MS1[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating client secret share 1: %v", rtn)
	}
	fmt.Printf("Client Secret share 1: 0x%x\n", CS1[:])

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	rtn, CS2 := GetClientSecret_BN254(MS2[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating client secret share 1: %v", rtn)
	}
	fmt.Printf("Client Secret share 2: 0x%x\n", CS2[:])

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_BN254)
	rtn, CS = RecombineG1_BN254(CS1[:], CS2[:])
	if rtn != 0 {
		log.Fatalf("error recombining client secret shares: %v", rtn)
	}
	fmt.Printf("Client Secret: 0x%x\n", CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	rtn, TP1 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS1[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating Time Permit share 1: %v", rtn)
	}
	fmt.Printf("Time Permit share 1: 0x%x\n", TP1[:])

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	rtn, TP2 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS2[:], HCID)
	if rtn != 0 {
		log.Fatalf("error generating Time Permit share 2: %v", rtn)
	}
	fmt.Printf("Time Permit share 2: 0x%x\n", TP2[:])

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	rtn, TP := RecombineG1_BN254(TP1[:], TP2[:])
	if rtn != 0 {
		log.Fatalf("error recombining Time Permit shares: %v", rtn)
	}

	// Destroy TP
	defer CleanMemory(TP[:])

	rtn, TOKEN := ExtractPIN_BN254(HASH_TYPE_MPIN, ID[:], PIN, CS[:])
	if rtn != 0 {
		log.Fatalf("error extracting pin from Client Secret: %v", rtn)
	}
	fmt.Printf("Token: 0x%x\n", TOKEN[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	//////   Client   //////

	////// Client Pass 1 //////
	// Send U and UT to server
	var X [PGS_BN254]byte
	rtn, XOut, SEC, U, UT := Client1_BN254(HASH_TYPE_MPIN, date, ID, rng, X[:], PIN, TOKEN[:], TP[:])
	if rtn != 0 {
		log.Fatalf("error client side MPin Full Pass 1: %v", rtn)
	}
	fmt.Printf("XOut: 0x%x\n", XOut[:])

	// Destroy X
	defer CleanMemory(X[:])
	// Destroy XOut
	defer CleanMemory(XOut[:])
	// Destroy SEC
	defer CleanMemory(SEC[:])

	//////   Server Pass 1  //////
	/* Calculate H(ID) and H(T|H(ID)) (if time permits enabled), and maps them to points on the curve HID and HTID resp. */
	HID, HTID := Server1_BN254(HASH_TYPE_MPIN, date, ID)

	/* Send Y to Client */
	rtn, Y := RandomGenerate_BN254(rng)
	if rtn != 0 {
		log.Fatalf("error generating Y: %v", rtn)
	}
	fmt.Printf("Y: 0x%x\n", Y[:])

	// Destroy Y
	defer CleanMemory(Y[:])

	/* Client Second Pass: Inputs Client secret SEC, x and y. Outputs -(x+y)*SEC */
	rtn, V := Client2_BN254(XOut[:], Y[:], SEC[:])
	if rtn != 0 {
		log.Fatalf("error client pass 2: %v", rtn)
	}

	// Destroy V
	defer CleanMemory(V[:])

	/* Server Second Pass. Inputs hashed client id, random Y, -(x+y)*SEC, xID and xCID and Server secret SST. E and F help Kangaroo_BN254s to find error. */
	/* If PIN error not required, set E and F = null */

	rtn, E, F := Server2_BN254(date, HID[:], HTID[:], nil, Y[:], SS[:], U[:], UT[:], V[:], true)
	if rtn != 0 {
		// authentication failed

		// check pin error
		err := Kangaroo_BN254(E[:], F[:])
		if err != 0 {
			log.Printf("error getting the PIN error: %v", err)
		}

		log.Fatalf("error server pass 2: %v", rtn)
	}
	fmt.Printf("HID: 0x%x\n", HID[:])
	fmt.Printf("HTID: 0x%x\n", HTID[:])

	fmt.Printf("Authenticated ID: %s \n", IDstr)

	// Output:
	// Master Secret share 1: 0x1dcdc0f9112e578e86e14dc6ac9e8e3656c9783a6275ae5df1fdd7a7156051dc
	// Master Secret share 2: 0x23f0b9b1afd4cae56af8331ed1225626bef35a012a65fe23ac819e45b6e2d4c2
	// Server Secret share 1: 0x18ed9d30343cc6381f1f361c72baeace9e601ca6a9479c3ff6797f792cf4634507ee4e81c62a515117076393961c74f22aa7a4df90775fa8aa513f568a6f18930d994d472ee81c8ea7cf2e9d700f9182e8c6ddb261c3ae2b77178c3f6783cdf80024e98b4f2f8e8a2ed8e6b9be3969f75a14d7b31ae1898ca5d3dc28e5f24163
	// Server Secret share 2: 0x07213b6c6210515a47d4aa70c2c5d7eaee11b00d2de329e39358e0f23b9237ee04017accdf6142d75943904f5623e3182e346d6d80e239403f0c0b6f44314c901545d04c0094eb123260a6ad17f4642de2753e4cb6962b5125c0c74636fe4f5f0728033b81a71cac68188f99b5e1b5e1f9d738aea040c91a7eafbde077596963
	// Server Secret: 0x0bc6d400159987574bf3618bd1f12640b1c4f82eb6119f6df16cb03010712088116cac4fb8b22917cd4c6a08433a55ddd4c3d4a4740cefca4ad5f15512793bbb08106f573aa4ce822ca361def6ca2f56da5fb2f3e4e4ab24f223dc25b11c4e9521328c5d3bec565b75d8cf6423867c8683182ea69845cd7079824ba7c64fae7f
	// Client Secret share 1: 0x041e210253763ab1dd23d7d0cf35d1ff88233fa5dd2b9ca59893c3743d8698c7a2211cb5670784f8f08bbffdabb8ee4834852414a48819b0bd226abdb50620f44a
	// Client Secret share 2: 0x0405ca872a20e803194126e282a2fb45a7b37cdfc40515a6045a7c3beb2bac29bb1b7462cd085de349e8ad1727814f735d8413a9d56b524b148d27e10d02c3f660
	// Client Secret: 0x04162e9f1048095fb44d549b7c9ef0f36662da47c93364f72f9f41a6c3361cd3a90770d92a46876f9e73cdce6609cdc7139cd22cd2908d2fc6a3ff20ece93c5750
	// Time Permit share 1: 0x0404c171f581824179675af09d9ef22dd9c50ca3a60270baaf8b906c3803ede9d10e88485278e55dab465b6289792fe3f66729cfe42820562095e1972315a6c1cd
	// Time Permit share 2: 0x0419226c66ebd7cefb7b6169c0762dbaa1d971a66a49837bc791be893282432e47151f25c931c03c82c563ee672f2210b4f7df9d3874c781ec18d8011f3db9009e
	// Token: 0x040bad25790c12811cbe7c5bc767540310e7a302f8ebb4bec5742bad961c3eb5c9023c4b41d16febccd9e5f66773beb93e9bbd6b640aba569bb2f07f0a143103e9
	// XOut: 0x2497b956d9193d707326c4fc7364744f7863d020efc2d2f8a86a864691e103d4
	// Y: 0x01c3545c4e07fe2cafcbc16ac110cc783fb17bdb03f2bca57a51be6fbefedc99
	// HID: 0x04144527fe508041db5eef90538f2547c4bd817d6dc94f67c7226585ec67706b0301a15ec8bff704176dab6371eae41ccc07a9c9b76e4be8162c56cb115e64024a
	// HTID: 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	// Authenticated ID: testUser@miracl.com
}
