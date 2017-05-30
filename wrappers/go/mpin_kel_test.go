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
	//"crypto/rand"
	"encoding/hex"
	"fmt"
	//mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (

	HASH_TYPE_MPIN = SHA256

	USE_ANONYMOUS = false

)

// Test with parameters for debug

// var (

// 	/* 
// 	 * Parameters for two pass custom test 
// 	 * Any parameter marked as "Supposed" is only for debug purposes and can be
// 	 * left empty, all the other ones are mandatory
// 	 */

// 	// M-Pin ID
// 	IDstr 	= "7b226973737565644174223a313439353132333036372c22757365724944223a227465737475736572406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a302c2273616c74223a226365343736383530386538396632643434653561653463333736653839316134222c2276223a317d"

// 	// DTA master secrets
// 	MS1str 	= "42e130af98bb4b9e8f416ca8c970d3928ef3a814d3e0239883e4f53fbec64bbf061c96e04304669e627171ff25d9ad56ec79f9da84f2de4cf8bc712b938f7c990d587e0292989295c748cf3dd7c1da711873a073f54c1bb60fd5a133ee57b168b861b69331f736cf8a362664db5dc5835caf6339c69ec567400f1be59cdcae42"
// 	MS2str 	= "42e130af98bb4b9e8f416ca8c970d3928ef3a814d3e0239883e4f53fbec64bbf061c96e04304669e627171ff25d9ad56ec79f9da84f2de4cf8bc712b938f7c990d587e0292989295c748cf3dd7c1da711873a073f54c1bb60fd5a133ee57b168b861b69331f736cf8a362664db5dc5835caf6339c69ec567400f1be59cdcae42"

// 	// Material for user public key
// 	Zstr 	= "1f451303822dd3543c41141285438e20387aefc1e08e987d90b02d6a492461e5"

// 	// x for U = x.A computation
// 	Xstr 	= "1ebe921aaf867e446aba8a3471bd55551275ebb26633ff54ab1e20ccf9a54e6c"

// 	// challenge y form server
// 	Ystr 	= "cc5b479eabdee092acd048538d60bc77abe35afbaa7f22fb74ef2e96a65a2b73"

// 	// Supposed ID|Pa
// 	IDPAstr = "7b226973737565644174223a313439353132333036372c22757365724944223a227465737475736572406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a302c2273616c74223a226365343736383530386538396632643434653561653463333736653839316134222c2276223a317d0a0433d1fc82a885f8c8e428030af82b8700e428c9d49dbd2fb452a898e89c19189ad8d6b644d028001e738f413c6e25c1aca3cf9d8243b36957c823ad36aab311d97939d541d16381ceeaa8735cfa7f4efce6cfed819ee0ab8465eb33a204e4043185eb11dba239ee5d75f0db2a37264ba82e4b1e7c8f948c97875ba001548d"

// 	// Supposed H(ID|Pa)
// 	HCIDstr = "3dcb0a44ef2f674c7d0ab5fa241ca60fd64cdb38eeafadc18df3ff0650d90c47"

// 	// Supposed server secret
// 	SSstr 	= "12f92c77d27231a16c7049464cc1fa79b586387ac2787fa107a9a9918351de3f01ba0b7797e8e99540e652b8dd88d9884eb71bdd1ea837da605252d1f78c03e00132dd50ad6c434f25d22de2efbe40d87bad538afbc2e3c90b058dab4b2b48b220360f7319bf659fd6df617c8c0a88a4fc4cb2e2e3aecf3b2bdf4a2c5b23eda0"

// 	// Supposed client secret before scalar multiplcation
// 	NCSstr 	= "040317ee4cb1b0b0b9c4d14c90225354fe796b106790945a060cadf3e862d9ba0e211d06a508369ccc2356020d3b63a0634d602ea3aeb0ca9482a35b38c1513108"

// 	// Supposed client secret after scalar multiplication
// 	CSstr 	= "041d4d86262709a189e4751bf273e39383d9ef1aef6fb9cfd89c19d3cf05b12e50077347e3f73443ad512402e81da655ae8431be97ff462794a51449e53af9a022"

// 	// Supposed Client1 outputs
// 	Ustr 	= "040400bd2bcde03e7bc9d96c9d4cb1223e67c6752c5315e31ada022547c1ef4d7c01718cd9dbfafc0926cbf2bd9da44f8a674d47c1140cf9ab0f068b3ec0547ed5"
// 	SECstr 	= "041d4d86262709a189e4751bf273e39383d9ef1aef6fb9cfd89c19d3cf05b12e50077347e3f73443ad512402e81da655ae8431be97ff462794a51449e53af9a022"

// 	// Supposed proof V from client
// 	Vstr 	= "04036efa0400b322e0f39dade4fbd34d8540bdd7dbf6c468c6939a6d011b60f4a22081919fb153d12e275c0e2538a032f542d2f41712dd97610bda7adb1a0f3d86"

// 	/* 
// 	 * Additional parameters for signature test 
// 	 * Any parameter marked as "Supposed" is only for debug purposes and can be
// 	 * left empty, all the other ones are mandatory
// 	 */

// 	// Timestamp of the signature
// 	TS 			= 1495184960

// 	// Hash to sign
// 	HsigStr		= "4b2287bbf06952d6113ec91a6cb80ae24c341f0b5c3375547f8c9e3734a16600"

// 	// x for U = x.A computation
// 	XsigStr 	= "1ebe921aaf867e446aba8a3471bd55551275ebb26633ff54ab1e20ccf9a54e6c"

// 	// Supposed ID|PA
// 	IDPAsigStr	= "7b226973737565644174223a313439353132333036372c22757365724944223a227465737475736572406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a302c2273616c74223a226365343736383530386538396632643434653561653463333736653839316134222c2276223a317d0a0433d1fc82a885f8c8e428030af82b8700e428c9d49dbd2fb452a898e89c19189ad8d6b644d028001e738f413c6e25c1aca3cf9d8243b36957c823ad36aab311d97939d541d16381ceeaa8735cfa7f4efce6cfed819ee0ab8465eb33a204e4043185eb11dba239ee5d75f0db2a37264ba82e4b1e7c8f948c97875ba001548d"

// 	// Supposed U
// 	UsigStr 	= "040400bd2bcde03e7bc9d96c9d4cb1223e67c6752c5315e31ada022547c1ef4d7c01718cd9dbfafc0926cbf2bd9da44f8a674d47c1140cf9ab0f068b3ec0547ed5"

// 	// Supposed y
// 	YsigStr 	= "0fd9c7da90f70e97b85803d7dab524c4b10fefbfa7f89bae607a195164239769"

// 	// Supposed token
// 	TOKsigStr 	= "041749247fea62e06140fea79bf671fb9a599cadee4292851ef5b9d7a9e4a3e01206bcb3446ebbd5fc0a48ab9caa26e95902c39e30573e2f59defa70547f73a379"

// 	// Supposed proof V from client
// 	VsigStr		= "0411e526054cf958494e6e7b460fb200d9bdd88163b7574e31914134f3d74271801b60efea24e6a840bc7d397a8ce036914c35cc2618114ee89acabe9ca2b50d76"

// )

// func TestParameters(t *testing.T) {
// 	want := 0
// 	var got int

// 	// Assign the End-User an ID
// 	ID, _ := hex.DecodeString(IDstr)
// 	fmt.Println("ID:",IDstr)

// 	// PIN variable to create token
// 	PIN1 := 1234
// 	// PIN variable to authenticate
// 	PIN2 := 1234

// 	// Generate Master Secret Share 1
// 	MS1, _ := hex.DecodeString(MS1str)

// 	// Destroy MS1
// 	defer CleanMemory(MS1[:])

// 	// Generate Master Secret Share 2
// 	MS2, _ := hex.DecodeString(MS2str)

// 	// Destroy MS2
// 	defer CleanMemory(MS2[:])

// 	// Generate Public Key
// 	Z, _ := hex.DecodeString(Zstr)
// 	_, _, Pa := GetClientPublicKey(nil, Z[:])
// 	fmt.Println("Z:", Zstr, "\nPa:", hex.EncodeToString(Pa))

// 	// Destroy Z
// 	defer CleanMemory(Z[:])

// 	// Compute ID|Pa 
// 	ID = append(ID,Pa...)
// 	fmt.Println("Supposed ID|Pa:",IDPAstr)
// 	fmt.Println("Actual   ID|Pa:",hex.EncodeToString(ID))

// 	// Either Client or TA calculates Hash(ID)
// 	HCID := HashId(HASH_TYPE_MPIN, ID)
// 	fmt.Println("Supposed HCID:",HCIDstr)
// 	fmt.Println("Actual   HCID:",hex.EncodeToString(HCID))

// 	// Generate server secret share 1
// 	_, SS1 := GetServerSecret(MS1[:])

// 	// Destroy SS1
// 	defer CleanMemory(SS1[:])

// 	// Generate server secret share 2
// 	_, SS2 := GetServerSecret(MS2[:])

// 	// Destroy SS2
// 	defer CleanMemory(SS2[:])

// 	// Combine server secret shares
// 	_, SS := RecombineG2(SS1[:], SS2[:])

// 	// Server secret
// 	fmt.Println("Supposed SS:",SSstr)
// 	fmt.Println("Actual   SS:",hex.EncodeToString(SS))

// 	// Destroy SS
// 	defer CleanMemory(SS[:])

// 	// Generate client secret share 1
// 	_, CS1 := GetClientSecret(MS1[:], HCID)

// 	// Destroy CS1
// 	defer CleanMemory(CS1[:])

// 	// Generate client secret share 2
// 	_, CS2 := GetClientSecret(MS2[:], HCID)

// 	// Destroy CS2
// 	defer CleanMemory(CS2[:])

// 	// Combine client secret shares
// 	CS := make([]byte, G1S)
// 	_, CS = RecombineG1(CS1[:], CS2[:])

// 	// Not multiplied secret
// 	fmt.Println("Supposed NCS:",NCSstr)
// 	fmt.Println("Actual   NCS:",hex.EncodeToString(CS))

// 	// Compute key-escrow less secret
// 	_, _, CS = GetG1Multiple(nil, 0, Z[:], CS[:])

// 	// key-escrow less client secret
// 	fmt.Println("Supposed CS:",CSstr)
// 	fmt.Println("Actual   CS:",hex.EncodeToString(CS))

// 	// Destroy CS
// 	defer CleanMemory(CS[:])

// 	// Create token
// 	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

// 	// Destroy TOKEN
// 	defer CleanMemory(TOKEN[:])

// 	/* TEST FOR M-PIN TWO PASS with custom parameters */
// 	fmt.Println("Test M-Pin two pass")

// 	// Client Pass 1
// 	X, _ := hex.DecodeString(Xstr)
// 	fmt.Println("X:",Xstr)

// 	_, _, SEC, U, _ := Client1(HASH_TYPE_MPIN, 0, ID, nil, X[:], PIN2, TOKEN[:], nil)

// 	fmt.Println("Supposed U:",Ustr)
// 	fmt.Println("Actual   U:",hex.EncodeToString(U))
// 	fmt.Println("Supposed SEC:",SECstr)
// 	fmt.Println("Actual   SEC:",hex.EncodeToString(SEC))
// 	fmt.Println("Original SEC:",CSstr)
// 	fmt.Println("O.actual SEC:",hex.EncodeToString(CS))

// 	// Destroy XOut
// 	defer CleanMemory(X[:])
// 	// Destroy SEC
// 	defer CleanMemory(SEC[:])

// 	// Server Pass 1
// 	var HID []byte
// 	if USE_ANONYMOUS {
// 		HID, _ = Server1(HASH_TYPE_MPIN, 0, HCID)
// 	} else {
// 		HID, _ = Server1(HASH_TYPE_MPIN, 0, ID)
// 	}
// 	Y, _ := hex.DecodeString(Ystr)
// 	fmt.Println("HID:",hex.EncodeToString(HID),"\nY:",Ystr)

// 	// Destroy HID
// 	defer CleanMemory(HID[:])
// 	// Destroy Y
// 	defer CleanMemory(Y[:])

// 	fmt.Println("Supposed V:",Vstr)
// 	// Client Pass 2
// 	_, V := Client2(X[:], Y[:], SEC[:])
// 	fmt.Println("Actual   V:", hex.EncodeToString(V))

// 	// Server Pass 2
// 	// Send UT as V to model bad token
// 	got, _, _ = Server2(0, HID[:], nil, Pa, Y[:], SS[:], U[:], nil, V[:], false)
// 	assert.Equal(t, want, got, "Should be equal")

// 	/* TEST FOR SIGNATURE USING M-PIN ONE PASS with custom parameters */
// 	fmt.Println("Test signature with M-Pin one pass")

// 	// Set X for signature
// 	X, _ = hex.DecodeString(XsigStr)
// 	fmt.Println("X:",XsigStr)

// 	// Set hash for signature
// 	H, _ := hex.DecodeString(HsigStr)
// 	fmt.Println("H:",HsigStr)
// 	fmt.Println("TS:",TS)



// 	// Send U, UT, V, timeValue and Message to serve
// 	_, _, Y, V, U, _ = Client(HASH_TYPE_MPIN, 0, ID[:], nil, X[:], PIN2, TOKEN[:], nil, H,  TS)

// 	// Destroy X
// 	defer CleanMemory(X[:])

// 	fmt.Println("Supposed X:",XsigStr)
// 	fmt.Println("Actual   X:",hex.EncodeToString(X))
// 	fmt.Println("Supposed ID|PA:",IDPAsigStr)
// 	fmt.Println("Actual   ID|PA:",hex.EncodeToString(ID))
// 	fmt.Println("Supposed U:",UsigStr)
// 	fmt.Println("Actual   U:",hex.EncodeToString(U))
// 	fmt.Println("Supposed Y:",YsigStr)
// 	fmt.Println("Actual   Y:",hex.EncodeToString(Y))
// 	fmt.Println("Supposed token:",TOKsigStr)
// 	fmt.Println("Actual   token:",hex.EncodeToString(TOKEN))
// 	fmt.Println("Supposed V:",VsigStr)
// 	fmt.Println("Actual   V:",hex.EncodeToString(V))

// 	// Authenticate
// 	if USE_ANONYMOUS {
// 		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, 0, TS, SS[:], U[:], nil, V[:], HCID[:], Pa, H, false)
// 	} else {
// 		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, 0, TS, SS[:], U[:], nil, V[:], ID[:], Pa, H, false)
// 	}
// 	assert.Equal(t, want, got, "Should be equal")

// }

func TestKeyEscrowLess(t *testing.T) {
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

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Generate Public Key
	_, Z := RandomGenerate(&rng)
	_, _, Pa := GetClientPublicKey(nil, Z[:])

	// Destroy Z
	defer CleanMemory(Z[:])

	// Compute ID|Pa 
	ID = append(ID,Pa...)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Compute key-escrow less secret
	_, _, CS = GetG1Multiple(nil, 0, Z[:], CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, _, _, V, U, _ := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], nil, nil,  timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	// Authenticate
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], nil, V[:], HCID[:], Pa, nil, false)
	} else {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], nil, V[:], ID[:], Pa, nil, false)
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestKeyEscrowLessRandom(t *testing.T) {
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

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Generate Public Key
	_, Z, Pa := GetClientPublicKey(&rng, nil)

	// Destroy Z
	defer CleanMemory(Z[:])

	// Compute ID|Pa 
	ID = append(ID,Pa...)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Compute key-escrow less secret
	_, _, CS = GetG1Multiple(nil, 0, Z[:], CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, _, _, V, U, _ := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], nil, nil,  timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	// Authenticate
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], nil, V[:], HCID[:], Pa, nil, false)
	} else {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], nil, V[:], ID[:], Pa, nil, false)
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestKeyEscrowWrongPK(t *testing.T) {
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

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Generate wrong Public Key
	_, Z, _  := GetClientPublicKey(&rng, nil)
	_, _, Pa := GetClientPublicKey(&rng, nil)

	// Destroy Z
	defer CleanMemory(Z[:])

	// Compute ID|Pa 
	ID = append(ID,Pa...)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Compute key-escrow less secret
	_, _, CS = GetG1Multiple(nil, 0, Z[:], CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	_, TP1 := GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	_, TP2 := GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	_, TP := RecombineG1(TP1[:], TP2[:])

	// Destroy TP
	defer CleanMemory(TP[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	// Send U, UT, V, timeValue and Message to server
	var X [PGS]byte
	_, _, _, V, U, UT := Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], nil,  timeValue)

	// Destroy X
	defer CleanMemory(X[:])

	timeValue += 10
	// Authenticate
	if USE_ANONYMOUS {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], Pa, nil, false)
	} else {
		got, _, _, _, _, _ = Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], Pa, nil, false)
	}
	assert.Equal(t, want, got, "Should be equal")
}

func TestKeyEscrowLessTwoPassWrongPK(t *testing.T) {
	want := -19
	var got int

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
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Generate wrong Public Key 
	_, Z := RandomGenerate(&rng)
	_, _, Pa := GetClientPublicKey(&rng, nil)

	// Destroy Z
	defer CleanMemory(Z[:])

	// Compute ID|Pa 
	ID = append(ID,Pa...)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Compute key-escrow less secret
	_, _, CS = GetG1Multiple(nil, 0, Z[:], CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	timeValue += 10
	// Client Pass 1
	var X [PGS]byte
	_, XOut, SEC, U, _ := Client1(HASH_TYPE_MPIN, 0, ID, &rng, X[:], PIN2, TOKEN[:], nil)

	// Destroy XOut
	defer CleanMemory(XOut[:])
	// Destroy SEC
	defer CleanMemory(SEC[:])

	// Server Pass 1
	var HID []byte
	if USE_ANONYMOUS {
		HID, _ = Server1(HASH_TYPE_MPIN, 0, HCID)
	} else {
		HID, _ = Server1(HASH_TYPE_MPIN, 0, ID)
	}
	_, Y := RandomGenerate(&rng)

	// Destroy HID
	defer CleanMemory(HID[:])
	// Destroy Y
	defer CleanMemory(Y[:])

	// Client Pass 2
	_, V := Client2(XOut[:], Y[:], SEC[:])

	// Server Pass 2
	// Send UT as V to model bad token
	got, _, _ = Server2(0, HID[:], nil, Pa, Y[:], SS[:], U[:], nil, V[:], false)
	assert.Equal(t, want, got, "Should be equal")
}

func TestKeyEscrowLessTwoPass(t *testing.T) {
	want := 0
	var got int

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
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	_, MS1 := RandomGenerate(&rng)

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	_, MS2 := RandomGenerate(&rng)

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Generate Public Key
	_, Z := RandomGenerate(&rng)
	_, _, Pa := GetClientPublicKey(nil, Z[:])

	// Destroy Z
	defer CleanMemory(Z[:])

	// Compute ID|Pa 
	ID = append(ID,Pa...)

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	_, SS1 := GetServerSecret(MS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	_, SS2 := GetServerSecret(MS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	_, SS := RecombineG2(SS1[:], SS2[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	_, CS1 := GetClientSecret(MS1[:], HCID)

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	_, CS2 := GetClientSecret(MS2[:], HCID)

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S)
	_, CS = RecombineG1(CS1[:], CS2[:])

	// Compute key-escrow less secret
	_, _, CS = GetG1Multiple(nil, 0, Z[:], CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Create token
	_, TOKEN := ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	timeValue += 10
	// Client Pass 1
	var X [PGS]byte
	_, XOut, SEC, U, _ := Client1(HASH_TYPE_MPIN, 0, ID, &rng, X[:], PIN2, TOKEN[:], nil)

	// Destroy XOut
	defer CleanMemory(XOut[:])
	// Destroy SEC
	defer CleanMemory(SEC[:])

	// Server Pass 1
	var HID []byte
	if USE_ANONYMOUS {
		HID, _ = Server1(HASH_TYPE_MPIN, 0, HCID)
	} else {
		HID, _ = Server1(HASH_TYPE_MPIN, 0, ID)
	}
	_, Y := RandomGenerate(&rng)

	// Destroy HID
	defer CleanMemory(HID[:])
	// Destroy Y
	defer CleanMemory(Y[:])

	// Client Pass 2
	_, V := Client2(XOut[:], Y[:], SEC[:])

	// Server Pass 2
	// Send UT as V to model bad token
	got, _, _ = Server2(0, HID[:], nil, Pa, Y[:], SS[:], U[:], nil, V[:], false)
	assert.Equal(t, want, got, "Should be equal")
}