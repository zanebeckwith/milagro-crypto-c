/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

package amcl

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var HASH_TYPE_MPIN = SHA256

const nIter int = 100

// Set to true if library built with "-D USE_ANONYMOUS=on"
const USE_ANONYMOUS = false

func TestGoodPIN(t *testing.T) {
	want := 0
	var got int

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
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}

	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, _, _, V, U, UT := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:])
	} else {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:])
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestBadPIN(t *testing.T) {
	want := -19
	var got int

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
	PIN2 := 1235

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}

	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, _, _, V, U, UT := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:])
	} else {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:])
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestBadToken(t *testing.T) {
	want := -19
	var got int

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
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}

	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, _, _, _, U, UT := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Send UT as V to model bad token
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], UT[:], HCID[:], MESSAGE[:])
	} else {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], UT[:], ID[:], MESSAGE[:])
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestRandom(t *testing.T) {
	want := 0
	var got int

	for i := 0; i < nIter; i++ {

		// Seed value for Random Number Generator (RNG)
		seed := make([]byte, 16)
		rand.Read(seed)
		rng := CreateCSPRNG(seed)

		// Epoch time in days
		date := Today()

		// Epoch time in seconds
		timeValue := GetTime()

		// PIN variable to create token
		PIN1 := mathrand.Intn(10000)
		// PIN variable to authenticate
		PIN2 := PIN1

		// Assign the End-User a random ID
		ID := make([]byte, 16)
		rand.Read(ID)

		// Message to sign
		var MESSAGE []byte

		// Generate Master Secret Share 1
		_, MS1 := RandomGenerate(&rng)

		// Generate Master Secret Share 2
		_, MS2 := RandomGenerate(&rng)

		// Either Client or TA calculates Hash(ID)
		HCID := HashId(HASH_TYPE_MPIN, ID)

		// Generate server secret share 1
		_, SS1 := GetServerSecret(MS1[:])

		// Generate server secret share 2
		_, SS2 := GetServerSecret(MS2[:])

		// Combine server secret shares
		_, SS := RecombineG2(SS1[:], SS2[:])

		// Generate client secret share 1
		_, CS1 := GetClientSecret(MS1[:], HCID)

		// Generate client secret share 2
		_, CS2 := GetClientSecret(MS2[:], HCID)

		// Combine client secret shares
		CS := make([]byte, G1S)
		_, CS = RecombineG1(CS1[:], CS2[:])

		// Generate time permit share 1
		_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

		// Generate time permit share 2
		_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

		// Combine time permit shares
		_, TP := RecombineG1(TP1[:], TP2[:])

		// Create token
		_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

		// Send U, UT, V, timeValue and Message to server
		var X [PGS]byte
		_, _, _, V, U, UT := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

		if USE_ANONYMOUS {
			got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:])
		} else {
			got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:])
		}
		assert.Equal(t, want, got, "Should be equal")
	}
}

func TestGoodSignature(t *testing.T) {
	want := 0
	var got int

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Message to sign
	MESSAGE := []byte("test message to sign")

	// Epoch time in days
	date := 16660

	// Epoch time in seconds
	timeValue := 1439465203

	// PIN variable to create token
	PIN1 := 1234
	// PIN variable to authenticate
	PIN2 := 1234

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, _, _, V, U, UT := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Authenticate
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:])
	} else {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:])
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestSignatureExpired(t *testing.T) {
	want := -19
	var got int

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Message to sign
	MESSAGE := []byte("test message to sign")

	// Epoch time in days
	date := 16660

	// Epoch time in seconds
	timeValue := 1439465203

	// PIN variable to create token
	PIN1 := 1234
	// PIN variable to authenticate
	PIN2 := 1234

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, _, _, V, U, UT := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	timeValue += 10
	// Authenticate
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:])
	} else {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:])
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestBadSignature(t *testing.T) {
	want := -19
	var got int

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Message to sign
	MESSAGE := []byte("test message to sign")

	// Epoch time in days
	date := 16660

	// Epoch time in seconds
	timeValue := 1439465203

	// PIN variable to create token
	PIN1 := 1234
	// PIN variable to authenticate
	PIN2 := 1234

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, _, _, V, U, UT := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Authenticate
	MESSAGE[0] = 00
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:])
	} else {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:])
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestPINError(t *testing.T) {
	want := 1001
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
	PIN2 := 2235

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, _, _, V, U, UT := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	var E []byte
	var F []byte
	if USE_ANONYMOUS {
		_, _, _, _, E, F = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:])
	} else {
		_, _, _, _, E, F = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:])
	}

	got := Kangaroo(E[:], F[:])
	assert.Equal(t, want, got, "Should be equal")
}

func TestMPINFull(t *testing.T) {
	want := "4e0317c9962dc2944c121ec41c800e16"
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
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Precomputation
	_, G1, G2 := Precompute(TOKEN[:], HCID)

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, XOut, _, V, U, UT := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Send Z=r.ID to Server
	var R [PGS]byte
	_, ROut, Z := GetG1Multiple(&rng, 1, R[:], HCID[:])

	// Authenticate
	var HID []byte
	var HTID []byte
	var Y []byte
	if USE_ANONYMOUS {
		_, HID, HTID, Y, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:])
	} else {
		_, HID, HTID, Y, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:])
	}

	// send T=w.ID to client
	var W [PGS]byte
	_, WOut, T := GetG1Multiple(&rng, 0, W[:], HTID[:])

	// Hash all values
	HM := HashAll(HASH_TYPE_MPIN, HCID[:], U[:], UT[:], Y[:], V[:], Z[:], T[:])

	_, AES_KEY_SERVER := ServerKey(HASH_TYPE_MPIN, Z[:], SS[:], WOut[:], HM[:], HID[:], U[:], UT[:])
	got := hex.EncodeToString(AES_KEY_SERVER[:])
	if got != want {
		t.Errorf("%s != %s", want, got)
	}

	_, AES_KEY_CLIENT := ClientKey(HASH_TYPE_MPIN, PIN2, G1[:], G2[:], ROut[:], XOut[:], HM[:], T[:])
	got = hex.EncodeToString(AES_KEY_CLIENT[:])

	assert.Equal(t, want, got, "Should be equal")
}

func TestTwoPassGoodPIN(t *testing.T) {
	want := 0
	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Epoch time in days
	date := 16660

	// PIN variable to create token
	PIN1 := 1234
	// PIN variable to authenticate
	PIN2 := 1234

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Client Pass 1
	var X [PGS]byte
	_, XOut, SEC, U, UT := Client1(HASH_TYPE_MPIN, date, ID, &rng, X[:], PIN2, TOKEN[:], TP[:])

	// Server Pass 1
	var HID []byte
	var HTID []byte
	if USE_ANONYMOUS {
		HID, HTID = Server1(HASH_TYPE_MPIN, date, HCID)
	} else {
		HID, HTID = Server1(HASH_TYPE_MPIN, date, ID)
	}
	_, Y := RandomGenerate(&rng)

	// Client Pass 2
	_, V := Client2(XOut[:], Y[:], SEC[:])

	// Server Pass 2
	got, _, _ := Server2(date, HID[:], HTID[:], Y[:], SS[:], U[:], UT[:], V[:])
	assert.Equal(t, want, got, "Should be equal")
}

func TestTwoPassBadPIN(t *testing.T) {
	want := -19
	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Epoch time in days
	date := 16660

	// PIN variable to create token
	PIN1 := 1234
	// PIN variable to authenticate
	PIN2 := 1235

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Client Pass 1
	var X [PGS]byte
	_, XOut, SEC, U, UT := Client1(HASH_TYPE_MPIN, date, ID, &rng, X[:], PIN2, TOKEN[:], TP[:])

	// Server Pass 1
	var HID []byte
	var HTID []byte
	if USE_ANONYMOUS {
		HID, HTID = Server1(HASH_TYPE_MPIN, date, HCID)
	} else {
		HID, HTID = Server1(HASH_TYPE_MPIN, date, ID)
	}
	_, Y := RandomGenerate(&rng)

	// Client Pass 2
	_, V := Client2(XOut[:], Y[:], SEC[:])

	// Server Pass 2
	got, _, _ := Server2(date, HID[:], HTID[:], Y[:], SS[:], U[:], UT[:], V[:])
	assert.Equal(t, want, got, "Should be equal")
}

func TestTwoPassBadToken(t *testing.T) {
	want := -19
	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Epoch time in days
	date := 16660

	// PIN variable to create token
	PIN1 := 1234
	// PIN variable to authenticate
	PIN2 := 1234

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Client Pass 1
	var X [PGS]byte
	_, XOut, SEC, U, UT := Client1(HASH_TYPE_MPIN, date, ID, &rng, X[:], PIN2, TOKEN[:], TP[:])

	// Server Pass 1
	var HID []byte
	var HTID []byte
	if USE_ANONYMOUS {
		HID, HTID = Server1(HASH_TYPE_MPIN, date, HCID)
	} else {
		HID, HTID = Server1(HASH_TYPE_MPIN, date, ID)
	}
	_, Y := RandomGenerate(&rng)

	// Client Pass 2
	_, _ = Client2(XOut[:], Y[:], SEC[:])

	// Server Pass 2
	// Send UT as V to model bad token
	got, _, _ := Server2(date, HID[:], HTID[:], Y[:], SS[:], U[:], UT[:], UT[:])
	assert.Equal(t, want, got, "Should be equal")
}

func TestRandomTwoPass(t *testing.T) {
	want := 0

	for i := 0; i < nIter; i++ {

		// Seed value for Random Number Generator (RNG)
		seed := make([]byte, 16)
		rand.Read(seed)
		rng := CreateCSPRNG(seed)

		// Epoch time in days
		date := Today()

		// PIN variable to create token
		PIN1 := mathrand.Intn(10000)
		// PIN variable to authenticate
		PIN2 := PIN1

		// Assign the End-User a random ID
		ID := make([]byte, 16)
		rand.Read(ID)

		// Generate Master Secret Share 1
		_, MS1 := RandomGenerate(&rng)

		// Generate Master Secret Share 2
		_, MS2 := RandomGenerate(&rng)

		// Either Client or TA calculates Hash(ID)
		HCID := HashId(HASH_TYPE_MPIN, ID)

		// Generate server secret share 1
		_, SS1 := GetServerSecret(MS1[:])

		// Generate server secret share 2
		_, SS2 := GetServerSecret(MS2[:])

		// Combine server secret shares
		_, SS := RecombineG2(SS1[:], SS2[:])

		// Generate client secret share 1
		_, CS1 := GetClientSecret(MS1[:], HCID)

		// Generate client secret share 2
		_, CS2 := GetClientSecret(MS2[:], HCID)

		// Combine client secret shares
		CS := make([]byte, G1S)
		_, CS = RecombineG1(CS1[:], CS2[:])

		// Generate time permit share 1
		_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

		// Generate time permit share 2
		_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

		// Combine time permit shares
		_, TP := RecombineG1(TP1[:], TP2[:])

		// Create token
		_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

		// Client Pass 1
		var X [PGS]byte
		_, XOut, SEC, U, UT := Client1(HASH_TYPE_MPIN, date, ID, &rng, X[:], PIN2, TOKEN[:], TP[:])

		// Server Pass 1
		var HID []byte
		var HTID []byte
		if USE_ANONYMOUS {
			HID, HTID = Server1(HASH_TYPE_MPIN, date, HCID)
		} else {
			HID, HTID = Server1(HASH_TYPE_MPIN, date, ID)
		}
		_, Y := RandomGenerate(&rng)

		// Client Pass 2
		_, V := Client2(XOut[:], Y[:], SEC[:])

		// Server Pass 2
		got, _, _ := Server2(date, HID[:], HTID[:], Y[:], SS[:], U[:], UT[:], V[:])
		assert.Equal(t, want, got, "Should be equal")

	}
}

func TestOctets(t *testing.T) {
	// Test bad hex
	oct := GetOctetHex("zz")
	assert.Equal(t, 0, int(oct.len), "Invalid hex should have len 0")
	// Test good hex
	oct = GetOctetHex("30")
	assert.Equal(t, 1, int(oct.len), "Hex octed doesn't match")
	oct = GetOctetHex("30")
	assert.Equal(t, 48, int(*oct.val), "Hex octed doesn't match")

	c := GetOctet(string([]byte{1, 2, 3}))
	h := OctetToHex(&c)

	rtn := int(OctetComp([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}))
	assert.Equal(t, rtn, 1, "Value should match 1")

	assert.Equal(t, "010203", h, "Octet convertion should match")
	s := OctetToString(&c)
	assert.Equal(t, "\x01\x02\x03", s, "Octet convertion should match")
}

func TestGenerateRandomByte(t *testing.T) {
	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	b := GenerateRandomByte(&rng, 10)
	assert.Equal(t, "57d662d39b1b245da469", fmt.Sprintf("%x", b), "Should be equal")
}

func TestGenerateOTP(t *testing.T) {
	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	otp := GenerateOTP(&rng)
	assert.Equal(t, 715827, otp, "Should be equal")
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
			C, T := AesGcmEncrypt(hexDecode(tc.Key), hexDecode(tc.IV), hexDecode(tc.AAD), hexDecode(tc.PlainText))
			assert.Equal(t, tc.outC, hex.EncodeToString(C), "Should be equal")
			assert.Equal(t, tc.outT, hex.EncodeToString(T), "Should be equal")

			dP, dT := AesGcmDecrypt(hexDecode(tc.Key), hexDecode(tc.IV), hexDecode(tc.AAD), hexDecode(tc.outC))
			assert.Equal(t, tc.PlainText, hex.EncodeToString(dP), "Should be equal")
			assert.Equal(t, tc.outT, hex.EncodeToString(dT), "Should be equal")
		})
	}
}
