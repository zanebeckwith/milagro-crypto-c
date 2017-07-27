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

// Set to true if library built with "-D USE_ANONYMOUS=on"
const USE_ANONYMOUS = false

func TestGoodPIN_ZZZ(t *testing.T) {
	want := 0
	var got int

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

	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_ZZZ]byte
	_, _, _, V, U, _ := Client_ZZZ(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], nil, MESSAGE[:], timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], nil, V[:], HCID[:], MESSAGE[:], false)
	} else {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], nil, V[:], ID[:], MESSAGE[:], false)
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestTimePermitGoodPIN_ZZZ(t *testing.T) {
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
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}

	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_ZZZ]byte
	_, _, _, V, U, UT := Client_ZZZ(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:], false)
	} else {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:], false)
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestBadPIN_ZZZ(t *testing.T) {
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
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}

	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_ZZZ]byte
	_, _, _, V, U, UT := Client_ZZZ(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:], false)
	} else {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:], false)
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestBadToken_ZZZ(t *testing.T) {
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
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}

	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_ZZZ]byte
	_, _, _, _, U, UT := Client_ZZZ(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	// Send UT as V to model bad token
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], UT[:], HCID[:], MESSAGE[:], false)
	} else {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], UT[:], ID[:], MESSAGE[:], false)
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestRandom_ZZZ(t *testing.T) {
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
		_, MS1 := RandomGenerate_ZZZ(&rng)

		// Destroy MS1
		defer CleanMemory(MS1[:])

		// Generate Master Secret Share 2
		_, MS2 := RandomGenerate_ZZZ(&rng)

		// Destroy MS2
		defer CleanMemory(MS2[:])

		// Either Client or TA calculates Hash(ID)
		HCID := HashId(HASH_TYPE_MPIN, ID)

		// Generate server secret share 1
		_, SS1 := GetServerSecret_ZZZ(MS1[:])

		// Destroy SS1
		defer CleanMemory(SS1[:])

		// Generate server secret share 2
		_, SS2 := GetServerSecret_ZZZ(MS2[:])

		// Destroy SS2
		defer CleanMemory(SS2[:])

		// Combine server secret shares
		_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

		// Destroy SS
		defer CleanMemory(SS[:])

		// Generate client secret share 1
		_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

		// Destroy CS1
		defer CleanMemory(CS1[:])

		// Generate client secret share 2
		_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

		// Destroy CS2
		defer CleanMemory(CS2[:])

		// Combine client secret shares
		CS := make([]byte, G1S_ZZZ)
		_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

		// Destroy CS
		defer CleanMemory(CS[:])

		// Generate time permit share 1
		_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

		// Destroy TP1
		defer CleanMemory(TP1[:])

		// Generate time permit share 2
		_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

		// Destroy TP2
		defer CleanMemory(TP2[:])

		// Combine time permit shares
		_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

		// Destroy TP
		defer CleanMemory(TP[:])

		// Create token
		_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

		// Destroy TOKEN
		defer CleanMemory(TOKEN[:])

		// Send U, UT, V, timeValue and Message to server
		var X [PGS_ZZZ]byte
		_, _, _, V, U, UT := Client_ZZZ(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

		// Destroy X
		defer CleanMemory(X[:])

		if USE_ANONYMOUS {
			got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:], false)
		} else {
			got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:], false)
		}
		assert.Equal(t, want, got, "Should be equal")
	}
}

func TestGoodSignature_ZZZ(t *testing.T) {
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
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_ZZZ]byte
	_, _, _, V, U, UT := Client_ZZZ(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	// Authenticate
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:], false)
	} else {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:], false)
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestSignatureExpired_ZZZ(t *testing.T) {
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
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_ZZZ]byte
	_, _, _, V, U, UT := Client_ZZZ(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	timeValue += 10
	// Authenticate
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:], false)
	} else {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:], false)
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestBadSignature_ZZZ(t *testing.T) {
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
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_ZZZ]byte
	_, _, _, V, U, UT := Client_ZZZ(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	// Authenticate
	MESSAGE[0] = 00
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:], false)
	} else {
		got, _, _, _, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:], false)
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestPINError_ZZZ(t *testing.T) {
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
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_ZZZ]byte
	_, _, _, V, U, UT := Client_ZZZ(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	var E []byte
	var F []byte
	if USE_ANONYMOUS {
		_, _, _, _, E, F = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:], true)
	} else {
		_, _, _, _, E, F = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:], true)
	}

	got := Kangaroo_ZZZ(E[:], F[:])
	assert.Equal(t, want, got, "Should be equal")
}

func TestMPINFull_ZZZ(t *testing.T) {
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
	rng := CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Precomputation
	_, G1, G2 := Precompute_ZZZ(TOKEN[:], HCID)

	// Destroy G1
	defer CleanMemory(G1[:])
	// Destroy G2
	defer CleanMemory(G2[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_ZZZ]byte
	_, XOut, _, V, U, UT := Client_ZZZ(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)

	// Destroy XOut
	defer CleanMemory(XOut[:])

	// Send Z=r.ID to Server
	var R [PGS_ZZZ]byte
	_, ROut, Z := GetG1Multiple_ZZZ(&rng, 1, R[:], HCID[:])

	// Destroy ROut
	defer CleanMemory(ROut[:])
	// Destroy Z
	defer CleanMemory(Z[:])

	// Authenticate
	var HID []byte
	var HTID []byte
	var Y []byte
	if USE_ANONYMOUS {
		_, HID, HTID, Y, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:], false)
	} else {
		_, HID, HTID, Y, _, _ = Server_ZZZ(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], MESSAGE[:], false)
	}

	// Destroy HID
	defer CleanMemory(HID[:])
	// Destroy HTID
	defer CleanMemory(HTID[:])
	// Destroy Y
	defer CleanMemory(Y[:])

	// send T=w.ID to client
	var W [PGS_ZZZ]byte
	_, WOut, T := GetG1Multiple_ZZZ(&rng, 0, W[:], HTID[:])

	// Destroy W
	defer CleanMemory(W[:])
	// Destroy WOut
	defer CleanMemory(WOut[:])
	// Destroy T
	defer CleanMemory(T[:])

	// Hash all values
	HM := HashAll(HASH_TYPE_MPIN, HCID[:], U[:], UT[:], Y[:], V[:], Z[:], T[:])

	// Destroy HM
	defer CleanMemory(HM[:])

	_, AES_KEY_SERVER := ServerKey_ZZZ(HASH_TYPE_MPIN, Z[:], SS[:], WOut[:], HM[:], HID[:], U[:], UT[:])

	// Destroy AES_KEY_SERVER
	defer CleanMemory(AES_KEY_SERVER[:])

	_, AES_KEY_CLIENT := ClientKey_ZZZ(HASH_TYPE_MPIN, PIN2, G1[:], G2[:], ROut[:], XOut[:], HM[:], T[:])

	// Destroy AES_KEY_CLIENT
	defer CleanMemory(AES_KEY_CLIENT[:])

	assert.Equal(t, AES_KEY_SERVER, AES_KEY_CLIENT, "Should be equal")
}

func TestTwoPassGoodPIN_ZZZ(t *testing.T) {
	want := 0
	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)

	// Epoch time in days
	date := 0

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
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Client Pass 1
	var X [PGS_ZZZ]byte
	_, XOut, SEC, U, _ := Client1_ZZZ(HASH_TYPE_MPIN, date, ID, &rng, X[:], PIN2, TOKEN[:], nil)

	// Destroy X
	defer CleanMemory(X[:])

	// Server Pass 1
	var HID []byte
	var HTID []byte
	if USE_ANONYMOUS {
		HID, HTID = Server1_ZZZ(HASH_TYPE_MPIN, date, HCID)
	} else {
		HID, HTID = Server1_ZZZ(HASH_TYPE_MPIN, date, ID)
	}
	_, Y := RandomGenerate_ZZZ(&rng)

	// Destroy HID
	defer CleanMemory(HID[:])
	// Destroy HTID
	defer CleanMemory(HTID[:])

	// Client Pass 2
	_, V := Client2_ZZZ(XOut[:], Y[:], SEC[:])

	// Destroy V
	defer CleanMemory(V[:])

	// Server Pass 2
	got, _, _ := Server2_ZZZ(date, HID[:], HTID[:], Y[:], SS[:], U[:], nil, V[:], false)

	assert.Equal(t, want, got, "Should be equal")
}

func TestTwoPassTimePermitGoodPIN_ZZZ(t *testing.T) {
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
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Client Pass 1
	var X [PGS_ZZZ]byte
	_, XOut, SEC, U, UT := Client1_ZZZ(HASH_TYPE_MPIN, date, ID, &rng, X[:], PIN2, TOKEN[:], TP[:])

	// Destroy X
	defer CleanMemory(X[:])

	// Server Pass 1
	var HID []byte
	var HTID []byte
	if USE_ANONYMOUS {
		HID, HTID = Server1_ZZZ(HASH_TYPE_MPIN, date, HCID)
	} else {
		HID, HTID = Server1_ZZZ(HASH_TYPE_MPIN, date, ID)
	}
	_, Y := RandomGenerate_ZZZ(&rng)

	// Destroy HID
	defer CleanMemory(HID[:])
	// Destroy HTID
	defer CleanMemory(HTID[:])

	// Client Pass 2
	_, V := Client2_ZZZ(XOut[:], Y[:], SEC[:])

	// Destroy V
	defer CleanMemory(V[:])

	// Server Pass 2
	got, _, _ := Server2_ZZZ(date, HID[:], HTID[:], Y[:], SS[:], U[:], UT[:], V[:], false)

	assert.Equal(t, want, got, "Should be equal")
}

func TestTwoPassBadPIN_ZZZ(t *testing.T) {
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
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Client Pass 1
	var X [PGS_ZZZ]byte
	_, XOut, SEC, U, UT := Client1_ZZZ(HASH_TYPE_MPIN, date, ID, &rng, X[:], PIN2, TOKEN[:], TP[:])

	// Destroy XOut
	defer CleanMemory(XOut[:])
	// Destroy SEC
	defer CleanMemory(SEC[:])

	// Server Pass 1
	var HID []byte
	var HTID []byte
	if USE_ANONYMOUS {
		HID, HTID = Server1_ZZZ(HASH_TYPE_MPIN, date, HCID)
	} else {
		HID, HTID = Server1_ZZZ(HASH_TYPE_MPIN, date, ID)
	}
	_, Y := RandomGenerate_ZZZ(&rng)

	// Destroy HID
	defer CleanMemory(HID[:])
	// Destroy HTID
	defer CleanMemory(HTID[:])
	// Destroy Y
	defer CleanMemory(Y[:])

	// Client Pass 2
	_, V := Client2_ZZZ(XOut[:], Y[:], SEC[:])

	// Destroy V
	defer CleanMemory(V[:])

	// Server Pass 2
	got, _, _ := Server2_ZZZ(date, HID[:], HTID[:], Y[:], SS[:], U[:], UT[:], V[:], false)
	assert.Equal(t, want, got, "Should be equal")
}

func TestTwoPassBadToken_ZZZ(t *testing.T) {
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
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate_ZZZ(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate_ZZZ(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret_ZZZ(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret_ZZZ(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_ZZZ)
	_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Client Pass 1
	var X [PGS_ZZZ]byte
	_, XOut, SEC, U, UT := Client1_ZZZ(HASH_TYPE_MPIN, date, ID, &rng, X[:], PIN2, TOKEN[:], TP[:])

	// Destroy XOut
	defer CleanMemory(XOut[:])
	// Destroy SEC
	defer CleanMemory(SEC[:])

	// Server Pass 1
	var HID []byte
	var HTID []byte
	if USE_ANONYMOUS {
		HID, HTID = Server1_ZZZ(HASH_TYPE_MPIN, date, HCID)
	} else {
		HID, HTID = Server1_ZZZ(HASH_TYPE_MPIN, date, ID)
	}
	_, Y := RandomGenerate_ZZZ(&rng)

	// Destroy HID
	defer CleanMemory(HID[:])
	// Destroy HTID
	defer CleanMemory(HTID[:])
	// Destroy Y
	defer CleanMemory(Y[:])

	// Client Pass 2
	_, _ = Client2_ZZZ(XOut[:], Y[:], SEC[:])

	// Server Pass 2
	// Send UT as V to model bad token
	got, _, _ := Server2_ZZZ(date, HID[:], HTID[:], Y[:], SS[:], U[:], UT[:], UT[:], false)
	assert.Equal(t, want, got, "Should be equal")
}

func TestRandomTwoPASS_ZZZ(t *testing.T) {
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
		_, MS1 := RandomGenerate_ZZZ(&rng)

		// Destroy MS1
		defer CleanMemory(MS1[:])

		// Generate Master Secret Share 2
		_, MS2 := RandomGenerate_ZZZ(&rng)

		// Destroy MS2
		defer CleanMemory(MS2[:])

		// Either Client or TA calculates Hash(ID)
		HCID := HashId(HASH_TYPE_MPIN, ID)

		// Generate server secret share 1
		_, SS1 := GetServerSecret_ZZZ(MS1[:])

		// Destroy SS1
		defer CleanMemory(SS1[:])

		// Generate server secret share 2
		_, SS2 := GetServerSecret_ZZZ(MS2[:])

		// Destroy SS2
		defer CleanMemory(SS2[:])

		// Combine server secret shares
		_, SS := RecombineG2_ZZZ(SS1[:], SS2[:])

		// Destroy SS
		defer CleanMemory(SS[:])

		// Generate client secret share 1
		_, CS1 := GetClientSecret_ZZZ(MS1[:], HCID)

		// Destroy CS1
		defer CleanMemory(CS1[:])

		// Generate client secret share 2
		_, CS2 := GetClientSecret_ZZZ(MS2[:], HCID)

		// Destroy CS2
		defer CleanMemory(CS2[:])

		// Combine client secret shares
		CS := make([]byte, G1S_ZZZ)
		_, CS = RecombineG1_ZZZ(CS1[:], CS2[:])

		// Destroy CS
		defer CleanMemory(CS[:])

		// Generate time permit share 1
		_, TP1 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS1[:], HCID)

		// Destroy TP1
		defer CleanMemory(TP1[:])

		// Generate time permit share 2
		_, TP2 := GetClientPermit_ZZZ(HASH_TYPE_MPIN, date, MS2[:], HCID)

		// Destroy TP2
		defer CleanMemory(TP2[:])

		// Combine time permit shares
		_, TP := RecombineG1_ZZZ(TP1[:], TP2[:])

		// Destroy TP
		defer CleanMemory(TP[:])

		// Create token
		_, TOKEN := ExtractPIN_ZZZ(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

		// Destroy TOKEN
		defer CleanMemory(TOKEN[:])

		// Client Pass 1
		var X [PGS_ZZZ]byte
		_, XOut, SEC, U, UT := Client1_ZZZ(HASH_TYPE_MPIN, date, ID, &rng, X[:], PIN2, TOKEN[:], TP[:])

		// Destroy XOut
		defer CleanMemory(XOut[:])
		// Destroy SEC
		defer CleanMemory(SEC[:])

		// Server Pass 1
		var HID []byte
		var HTID []byte
		if USE_ANONYMOUS {
			HID, HTID = Server1_ZZZ(HASH_TYPE_MPIN, date, HCID)
		} else {
			HID, HTID = Server1_ZZZ(HASH_TYPE_MPIN, date, ID)
		}
		_, Y := RandomGenerate_ZZZ(&rng)

		// Destroy Y
		defer CleanMemory(Y[:])

		// Client Pass 2
		_, V := Client2_ZZZ(XOut[:], Y[:], SEC[:])

		// Destroy V
		defer CleanMemory(V[:])

		// Server Pass 2
		got, _, _ := Server2_ZZZ(date, HID[:], HTID[:], Y[:], SS[:], U[:], UT[:], V[:], false)
		assert.Equal(t, want, got, "Should be equal")

	}
}

