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
	"sync"
	"time"
)

// ExampleMPinAuthentication is example for single MPin authentication
func ExampleMPinAuthentication() {
	// Seed value for Random Number Generator (RNG)
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	HASH_TYPE_MPIN := SHA256

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)
	fmt.Printf("ID: ")
	fmt.Printf("%x\n\n", ID)

	// Epoch time in days
	date := Today()
	fmt.Println("date: ", date)

	// Epoch time in seconds
	timeValue := GetTime()
	fmt.Println("timeValue: ", timeValue)

	// PIN variable to create token
	PIN1 := -1
	// PIN variable to authenticate
	PIN2 := -1

	// Message to sign
	var MESSAGE []byte
	// MESSAGE := []byte("test sign message")

	// Generate Master Secret Share 1
	rtn, MS1 := RandomGenerate_BN254(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate_BN254 Error:", rtn)
		return
	}
	fmt.Printf("MS1: 0x")
	fmt.Printf("%x\n", MS1[:])

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	rtn, MS2 := RandomGenerate_BN254(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate_BN254 Error:", rtn)
		return
	}
	fmt.Printf("MS2: 0x")
	fmt.Printf("%x\n", MS2[:])

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, PFS_BN254, ID)

	// Generate server secret share 1
	rtn, SS1 := GetServerSecret_BN254(MS1[:])
	if rtn != 0 {
		fmt.Println("GetServerSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("SS1: 0x")
	fmt.Printf("%x\n", SS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	rtn, SS2 := GetServerSecret_BN254(MS2[:])
	if rtn != 0 {
		fmt.Println("GetServerSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("SS2: 0x")
	fmt.Printf("%x\n", SS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	rtn, SS := RecombineG2_BN254(SS1[:], SS2[:])
	if rtn != 0 {
		fmt.Println("RecombineG2_BN254(SS1, SS2) Error:", rtn)
		return
	}
	fmt.Printf("SS: 0x")
	fmt.Printf("%x\n", SS[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	rtn, CS1 := GetClientSecret_BN254(MS1[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret Share CS1: 0x")
	fmt.Printf("%x\n", CS1[:])

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	rtn, CS2 := GetClientSecret_BN254(MS2[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret Share CS2: 0x")
	fmt.Printf("%x\n", CS2[:])

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_BN254)
	rtn, CS = RecombineG1_BN254(CS1[:], CS2[:])
	if rtn != 0 {
		fmt.Println("RecombineG1_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret CS: 0x")
	fmt.Printf("%x\n", CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	rtn, TP1 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS1[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientPermit_BN254 Error:", rtn)
		return
	}
	fmt.Printf("TP1: 0x")
	fmt.Printf("%x\n", TP1[:])

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	rtn, TP2 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS2[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientPermit_BN254 Error:", rtn)
		return
	}
	fmt.Printf("TP2: 0x")
	fmt.Printf("%x\n", TP2[:])

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	rtn, TP := RecombineG1_BN254(TP1[:], TP2[:])
	if rtn != 0 {
		fmt.Println("RecombineG1_BN254(TP1, TP2) Error:", rtn)
		return
	}

	// Destroy TP
	defer CleanMemory(TP[:])

	// Client extracts PIN1 from secret to create Token
	for PIN1 < 0 {
		fmt.Printf("Please enter PIN to create token: ")
		fmt.Scan(&PIN1)
	}

	rtn, TOKEN := ExtractPIN_BN254(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: EXTRACT_PIN rtn: %d\n", rtn)
		return
	}
	fmt.Printf("Client Token TK: 0x")
	fmt.Printf("%x\n", TOKEN[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	//////   Client   //////

	for PIN2 < 0 {
		fmt.Printf("Please enter PIN to authenticate: ")
		fmt.Scan(&PIN2)
	}

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_BN254]byte
	fmt.Printf("X: 0x")
	fmt.Printf("%x\n", X[:])
	rtn, XOut, Y1, SEC, U, UT := Client_BN254(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)
	if rtn != 0 {
		fmt.Printf("FAILURE: CLIENT rtn: %d\n", rtn)
		return
	}
	fmt.Printf("Y1: 0x")
	fmt.Printf("%x\n", Y1[:])
	fmt.Printf("XOut: 0x")
	fmt.Printf("%x\n", XOut[:])
	fmt.Printf("V: 0x")
	fmt.Printf("%x\n", SEC[:])

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
		fmt.Printf("FAILURE: SERVER rtn: %d\n", rtn)
	}
	fmt.Printf("Y2: 0x")
	fmt.Printf("%x\n", Y2[:])
	fmt.Printf("HID: 0x")
	fmt.Printf("%x\n", HID[:])
	fmt.Printf("HTID: 0x")
	fmt.Printf("%x\n", HTID[:])

	// Destroy Y2
	defer CleanMemory(Y2[:])
	// Destroy E
	defer CleanMemory(E[:])
	// Destroy F
	defer CleanMemory(F[:])

	if rtn != 0 {
		fmt.Printf("Authentication failed Error Code %d\n", rtn)
		err := Kangaroo_BN254(E[:], F[:])
		if err != 0 {
			fmt.Printf("PIN Error %d\n", err)
		}
		return
	} else {
		fmt.Printf("Authenticated ID: %s \n", IDstr)
	}
}

// ExampleMPinAuthentications is example for concurrent MPin authentications
func ExampleMPinAuthentications() {
	numRoutines := 1000

	// Seed value for Random Number Generator (RNG)
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	wg := sync.WaitGroup{}

	fmt.Printf("Stating %v go routines...\n", numRoutines)
	wg.Add(numRoutines)
	t := time.Now()
	for x := 0; x < numRoutines; x++ {
		go func(rng *RandNG, wg *sync.WaitGroup) {
			HASH_TYPE_MPIN := SHA256

			// Assign the End-User an ID
			IDstr := "testUser@miracl.com"
			ID := []byte(IDstr)

			// Epoch time in days
			date := Today()

			// Epoch time in seconds
			timeValue := GetTime()

			// PIN variable to create token
			PIN := 1111

			// Message to sign
			MESSAGE := []byte("test sign message")

			// Generate Master Secret Share 1
			rtn, MS1 := RandomGenerate_BN254(rng)
			if rtn != 0 {
				fmt.Println("RandomGenerate_BN254 Error:", rtn)
				return
			}
			// Destroy MS1
			defer CleanMemory(MS1[:])

			// Generate Master Secret Share 2
			rtn, MS2 := RandomGenerate_BN254(rng)
			if rtn != 0 {
				fmt.Println("RandomGenerate_BN254 Error:", rtn)
				return
			}
			// Destroy MS2
			defer CleanMemory(MS2[:])

			// Either Client or TA calculates Hash(ID)
			HCID := HashId(HASH_TYPE_MPIN, PFS_BN254, ID)

			// Generate server secret share 1
			rtn, SS1 := GetServerSecret_BN254(MS1[:])
			if rtn != 0 {
				fmt.Println("GetServerSecret_BN254 Error:", rtn)
				return
			}
			// Destroy SS1
			defer CleanMemory(SS1[:])

			// Generate server secret share 2
			rtn, SS2 := GetServerSecret_BN254(MS2[:])
			if rtn != 0 {
				fmt.Println("GetServerSecret_BN254 Error:", rtn)
				return
			}
			// Destroy SS2
			defer CleanMemory(SS2[:])

			// Combine server secret shares
			rtn, SS := RecombineG2_BN254(SS1[:], SS2[:])
			if rtn != 0 {
				fmt.Println("RecombineG2_BN254(SS1, SS2) Error:", rtn)
				return
			}
			// Destroy SS
			defer CleanMemory(SS[:])

			// Generate client secret share 1
			rtn, CS1 := GetClientSecret_BN254(MS1[:], HCID)
			if rtn != 0 {
				fmt.Println("GetClientSecret_BN254 Error:", rtn)
				return
			}
			// Destroy CS1
			defer CleanMemory(CS1[:])

			// Generate client secret share 2
			rtn, CS2 := GetClientSecret_BN254(MS2[:], HCID)
			if rtn != 0 {
				fmt.Println("GetClientSecret_BN254 Error:", rtn)
				return
			}
			// Destroy CS2
			defer CleanMemory(CS2[:])

			// Combine client secret shares
			CS := make([]byte, G1S_BN254)
			rtn, CS = RecombineG1_BN254(CS1[:], CS2[:])
			if rtn != 0 {
				fmt.Println("RecombineG1_BN254 Error:", rtn, SS, CS)
				return
			}
			// Destroy CS
			defer CleanMemory(CS[:])

			// Generate time permit share 1
			rtn, TP1 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS1[:], HCID)
			if rtn != 0 {
				fmt.Println("GetClientPermit_BN254 Error:", rtn)
				return
			}
			// Destroy TP1
			defer CleanMemory(TP1[:])

			// Generate time permit share 2
			rtn, TP2 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS2[:], HCID)
			if rtn != 0 {
				fmt.Println("GetClientPermit_BN254 Error:", rtn)
				return
			}
			// Destroy TP2
			defer CleanMemory(TP2[:])

			// Combine time permit shares
			rtn, TP := RecombineG1_BN254(TP1[:], TP2[:])
			if rtn != 0 {
				fmt.Println("RecombineG1_BN254(TP1, TP2) Error:", rtn, TP)
				return
			}
			// Destroy TP
			defer CleanMemory(TP[:])

			rtn, TOKEN := ExtractPIN_BN254(HASH_TYPE_MPIN, ID[:], PIN, CS[:])
			if rtn != 0 {
				fmt.Printf("FAILURE: EXTRACT_PIN rtn: %d\n", rtn)
				return
			}
			// Destroy TOKEN
			defer CleanMemory(TOKEN[:])

			// --- Client ---
			// Send U, UT, V, timeValue and Message to server
			var X [PGS_BN254]byte
			rtn, _, _, SEC, U, UT := Client_BN254(HASH_TYPE_MPIN, date, ID[:], rng, X[:], PIN, TOKEN[:], TP[:], MESSAGE[:], timeValue)
			if rtn != 0 {
				fmt.Printf("FAILURE: CLIENT rtn: %d\n", rtn, SEC, U, UT)
				return
			}

			// --- Server ---
			rtn, _, _, _, E, F := Server_BN254(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], SEC[:], ID[:], nil, MESSAGE[:], true)
			if rtn != 0 {
				fmt.Printf("FAILURE: SERVER rtn: %d\n", rtn)
			}
			if rtn != 0 {
				fmt.Printf("Authentication failed Error Code %d\n", rtn)
				err := Kangaroo_BN254(E[:], F[:])
				if err != 0 {
					fmt.Printf("PIN Error %d\n", err)
				}
				return
			}

			wg.Done()
		}(&rng, &wg)
	}
	wg.Wait()

	fmt.Printf("Done: %v \n", time.Now().Sub(t).Seconds())
}

// ExampleMPinFull is example for MPin full work-flow
func ExampleMPinFull() {
	HASH_TYPE_MPIN := SHA256

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)
	fmt.Printf("ID: ")
	fmt.Printf("%x\n\n", ID)

	// Epoch time in days
	date := 0
	fmt.Println("date: ", date)

	// Epoch time in seconds
	timeValue := GetTime()
	fmt.Println("timeValue: ", timeValue)

	// PIN variable to create token
	PIN1 := 0
	// PIN variable to authenticate
	PIN2 := 0

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
	// MESSAGE := []byte("test sign message")

	// Generate Master Secret Share 1
	rtn, MS1 := RandomGenerate_BN254(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate_BN254 Error:", rtn)
		return
	}
	fmt.Printf("MS1: 0x")
	fmt.Printf("%x\n", MS1[:])

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	rtn, MS2 := RandomGenerate_BN254(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate_BN254 Error:", rtn)
		return
	}
	fmt.Printf("MS2: 0x")
	fmt.Printf("%x\n", MS2[:])

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, PFS_BN254, ID)

	// Generate server secret share 1
	rtn, SS1 := GetServerSecret_BN254(MS1[:])
	if rtn != 0 {
		fmt.Println("GetServerSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("SS1: 0x")
	fmt.Printf("%x\n", SS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	rtn, SS2 := GetServerSecret_BN254(MS2[:])
	if rtn != 0 {
		fmt.Println("GetServerSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("SS2: 0x")
	fmt.Printf("%x\n", SS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	rtn, SS := RecombineG2_BN254(SS1[:], SS2[:])
	if rtn != 0 {
		fmt.Println("RecombineG2_BN254(SS1, SS2) Error:", rtn)
		return
	}
	fmt.Printf("SS: 0x")
	fmt.Printf("%x\n", SS[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	rtn, CS1 := GetClientSecret_BN254(MS1[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret Share CS1: 0x")
	fmt.Printf("%x\n", CS1[:])

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	rtn, CS2 := GetClientSecret_BN254(MS2[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret Share CS2: 0x")
	fmt.Printf("%x\n", CS2[:])

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_BN254)
	rtn, CS = RecombineG1_BN254(CS1[:], CS2[:])
	if rtn != 0 {
		fmt.Println("RecombineG1_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret CS: 0x")
	fmt.Printf("%x\n", CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Client extracts PIN1 from secret to create Token
	for PIN1 < 0 {
		fmt.Printf("Please enter PIN to create token: ")
		fmt.Scan(&PIN1)
	}

	rtn, TOKEN := ExtractPIN_BN254(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: EXTRACT_PIN rtn: %d\n", rtn)
		return
	}
	fmt.Printf("Client Token TK: 0x")
	fmt.Printf("%x\n", TOKEN[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	//////   Client   //////

	// Precomputation
	rtn, G1, G2 := Precompute_BN254(TOKEN[:], HCID)
	if rtn != 0 {
		fmt.Println("Precompute_BN254(TOKEN[:], HCID) Error:", rtn)
		return
	}

	// Destroy G2
	defer CleanMemory(G2[:])
	// Destroy G1
	defer CleanMemory(G1[:])

	for PIN2 < 0 {
		fmt.Printf("Please enter PIN to authenticate: ")
		fmt.Scan(&PIN2)
	}

	// Send U, V, timeValue and Message to server
	var X [PGS_BN254]byte
	fmt.Printf("X: 0x")
	fmt.Printf("%x\n", X[:])
	rtn, XOut, Y1, V, U, _ := Client_BN254(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], nil, MESSAGE[:], timeValue)
	if rtn != 0 {
		fmt.Printf("FAILURE: CLIENT rtn: %d\n", rtn)
		return
	}
	fmt.Printf("Y1: 0x")
	fmt.Printf("%x\n", Y1[:])
	fmt.Printf("XOut: 0x")
	fmt.Printf("%x\n", XOut[:])

	// Destroy Y1
	defer CleanMemory(Y1[:])
	// Destroy XOut
	defer CleanMemory(XOut[:])
	// Destroy V
	defer CleanMemory(V[:])

	// Send Z=r.ID to Server
	var R [PGS_BN254]byte
	fmt.Printf("R: 0x")
	fmt.Printf("%x\n", R[:])
	rtn, ROut, Z := GetG1Multiple_BN254(&rng, 1, R[:], HCID[:])
	fmt.Printf("ROut: 0x")
	fmt.Printf("%x\n", ROut[:])

	// Destroy R
	defer CleanMemory(R[:])
	// Destroy ROut
	defer CleanMemory(ROut[:])
	// Destroy Z
	defer CleanMemory(Z[:])

	//////   Server   //////
	rtn, HID, _, Y2, E, F := Server_BN254(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], nil, V[:], ID[:], nil, MESSAGE[:], true)
	if rtn != 0 {
		fmt.Printf("FAILURE: SERVER rtn: %d\n", rtn)
	}
	fmt.Printf("Y2: 0x")
	fmt.Printf("%x\n", Y2[:])
	fmt.Printf("HID: 0x")
	fmt.Printf("%x\n", HID[:])

	// Destroy Y2
	defer CleanMemory(Y2[:])
	// Destroy E
	defer CleanMemory(E[:])
	// Destroy F
	defer CleanMemory(F[:])

	if rtn != 0 {
		fmt.Printf("Authentication failed Error Code %d\n", rtn)
		err := Kangaroo_BN254(E[:], F[:])
		if err != 0 {
			fmt.Printf("PIN Error %d\n", err)
		}
		return
	} else {
		fmt.Printf("Authenticated ID: %s \n", IDstr)
	}

	// send T=w.ID to client
	var W [PGS_BN254]byte
	fmt.Printf("W: 0x")
	fmt.Printf("%x\n", W[:])
	rtn, WOut, T := GetG1Multiple_BN254(&rng, 0, W[:], HID[:])
	fmt.Printf("WOut: 0x")
	fmt.Printf("%x\n", WOut[:])
	fmt.Printf("T: 0x")
	fmt.Printf("%x\n", T[:])

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
	fmt.Printf("RTN = %v Server Key =  %x\n", rtn, AES_KEY_SERVER[:])

	// Destroy AES_KEY_SERVER
	defer CleanMemory(AES_KEY_SERVER[:])

	rtn, AES_KEY_CLIENT := ClientKey_BN254(HASH_TYPE_MPIN, PIN2, G1[:], G2[:], ROut[:], XOut[:], HM[:], T[:])
	fmt.Printf("Client Key =  0x")
	fmt.Printf("%x\n", AES_KEY_CLIENT[:])

	// Destroy AES_KEY_CLIENT
	defer CleanMemory(AES_KEY_CLIENT[:])

	//////   Server   //////

	// Initialization vector
	IV := GenerateRandomByte(&rng, 12)
	fmt.Printf("IV: 0x")
	fmt.Printf("%x\n", IV[:])

	// Destroy IV
	defer CleanMemory(IV[:])

	// header
	HEADER := GenerateRandomByte(&rng, 16)
	fmt.Printf("HEADER: 0x")
	fmt.Printf("%x\n", HEADER[:])

	// Destroy HEADER
	defer CleanMemory(HEADER[:])

	// Input plaintext
	plaintextStr := "A test message"
	PLAINTEXT1 := []byte(plaintextStr)
	fmt.Printf("String to encrypt: %s \n", plaintextStr)
	fmt.Printf("PLAINTEXT1: 0x")
	fmt.Printf("%x\n", PLAINTEXT1[:])

	// Destroy PLAINTEXT1
	defer CleanMemory(PLAINTEXT1[:])

	// AES-GCM Encryption
	CIPHERTEXT, TAG1, err := AesGcmEncrypt(AES_KEY_SERVER[:], IV[:], HEADER[:], PLAINTEXT1[:])
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("CIPHERTEXT:  0x")
	fmt.Printf("%x\n", CIPHERTEXT[:])
	fmt.Printf("TAG1:  0x")
	fmt.Printf("%x\n", TAG1[:])

	// Destroy CIPHERTEXT
	defer CleanMemory(CIPHERTEXT[:])
	// Destroy TAG1
	defer CleanMemory(TAG1[:])

	// Send IV, HEADER, CIPHERTEXT and TAG1 to client

	// AES-GCM Decryption
	PLAINTEXT2, TAG2, err := AesGcmDecrypt(AES_KEY_CLIENT[:], IV[:], HEADER[:], CIPHERTEXT[:])
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("PLAINTEXT2:  0x")
	fmt.Printf("%x\n", PLAINTEXT2[:])
	fmt.Printf("TAG2:  0x")
	fmt.Printf("%x\n", TAG2[:])
	fmt.Printf("Decrypted string: %s \n", string(PLAINTEXT2))

	// Destroy PLAINTEXT2
	defer CleanMemory(PLAINTEXT2[:])
	// Destroy TAG2
	defer CleanMemory(TAG2[:])
}

// ExampleMPinFullWithTP is example for MPin full work-flow with time permits
func ExampleMPinFullWithTP() {
	HASH_TYPE_MPIN := SHA256

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)
	fmt.Printf("ID: ")
	fmt.Printf("%x\n\n", ID)

	// Epoch time in days
	date := Today()
	fmt.Println("date: ", date)

	// Epoch time in seconds
	timeValue := GetTime()
	fmt.Println("timeValue: ", timeValue)

	// PIN variable to create token
	PIN1 := -1
	// PIN variable to authenticate
	PIN2 := -1

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
	// MESSAGE := []byte("test sign message")

	// Generate Master Secret Share 1
	rtn, MS1 := RandomGenerate_BN254(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate_BN254 Error:", rtn)
		return
	}
	fmt.Printf("MS1: 0x")
	fmt.Printf("%x\n", MS1[:])

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	rtn, MS2 := RandomGenerate_BN254(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate_BN254 Error:", rtn)
		return
	}
	fmt.Printf("MS2: 0x")
	fmt.Printf("%x\n", MS2[:])

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, PFS_BN254, ID)

	// Generate server secret share 1
	rtn, SS1 := GetServerSecret_BN254(MS1[:])
	if rtn != 0 {
		fmt.Println("GetServerSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("SS1: 0x")
	fmt.Printf("%x\n", SS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	rtn, SS2 := GetServerSecret_BN254(MS2[:])
	if rtn != 0 {
		fmt.Println("GetServerSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("SS2: 0x")
	fmt.Printf("%x\n", SS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	rtn, SS := RecombineG2_BN254(SS1[:], SS2[:])
	if rtn != 0 {
		fmt.Println("RecombineG2_BN254(SS1, SS2) Error:", rtn)
		return
	}
	fmt.Printf("SS: 0x")
	fmt.Printf("%x\n", SS[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	rtn, CS1 := GetClientSecret_BN254(MS1[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret Share CS1: 0x")
	fmt.Printf("%x\n", CS1[:])

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	rtn, CS2 := GetClientSecret_BN254(MS2[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret Share CS2: 0x")
	fmt.Printf("%x\n", CS2[:])

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_BN254)
	rtn, CS = RecombineG1_BN254(CS1[:], CS2[:])
	if rtn != 0 {
		fmt.Println("RecombineG1_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret CS: 0x")
	fmt.Printf("%x\n", CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	rtn, TP1 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS1[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientPermit_BN254 Error:", rtn)
		return
	}
	fmt.Printf("TP1: 0x")
	fmt.Printf("%x\n", TP1[:])

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	rtn, TP2 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS2[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientPermit_BN254 Error:", rtn)
		return
	}
	fmt.Printf("TP2: 0x")
	fmt.Printf("%x\n", TP2[:])

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	rtn, TP := RecombineG1_BN254(TP1[:], TP2[:])
	if rtn != 0 {
		fmt.Println("RecombineG1_BN254(TP1, TP2) Error:", rtn)
		return
	}

	// Destroy TP
	defer CleanMemory(TP[:])

	// Client extracts PIN1 from secret to create Token
	for PIN1 < 0 {
		fmt.Printf("Please enter PIN to create token: ")
		fmt.Scan(&PIN1)
	}

	rtn, TOKEN := ExtractPIN_BN254(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: EXTRACT_PIN rtn: %d\n", rtn)
		return
	}
	fmt.Printf("Client Token TK: 0x")
	fmt.Printf("%x\n", TOKEN[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	//////   Client   //////

	// Precomputation
	rtn, G1, G2 := Precompute_BN254(TOKEN[:], HCID)
	if rtn != 0 {
		fmt.Println("Precompute_BN254(TOKEN[:], HCID) Error:", rtn)
		return
	}

	// Destroy G2
	defer CleanMemory(G2[:])
	// Destroy G1
	defer CleanMemory(G1[:])

	for PIN2 < 0 {
		fmt.Printf("Please enter PIN to authenticate: ")
		fmt.Scan(&PIN2)
	}

	// Send U, UT, V, timeValue and Message to server
	var X [PGS_BN254]byte
	fmt.Printf("X: 0x")
	fmt.Printf("%x\n", X[:])
	rtn, XOut, Y1, V, U, UT := Client_BN254(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)
	if rtn != 0 {
		fmt.Printf("FAILURE: CLIENT rtn: %d\n", rtn)
		return
	}
	fmt.Printf("Y1: 0x")
	fmt.Printf("%x\n", Y1[:])
	fmt.Printf("XOut: 0x")
	fmt.Printf("%x\n", XOut[:])

	// Destroy Y1
	defer CleanMemory(Y1[:])
	// Destroy XOut
	defer CleanMemory(XOut[:])
	// Destroy V
	defer CleanMemory(V[:])

	// Send Z=r.ID to Server
	var R [PGS_BN254]byte
	fmt.Printf("R: 0x")
	fmt.Printf("%x\n", R[:])
	rtn, ROut, Z := GetG1Multiple_BN254(&rng, 1, R[:], HCID[:])
	fmt.Printf("ROut: 0x")
	fmt.Printf("%x\n", ROut[:])

	// Destroy R
	defer CleanMemory(R[:])
	// Destroy ROut
	defer CleanMemory(ROut[:])
	// Destroy Z
	defer CleanMemory(Z[:])

	//////   Server   //////
	rtn, HID, HTID, Y2, E, F := Server_BN254(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], ID[:], nil, MESSAGE[:], true)
	if rtn != 0 {
		fmt.Printf("FAILURE: SERVER rtn: %d\n", rtn)
	}
	fmt.Printf("Y2: 0x")
	fmt.Printf("%x\n", Y2[:])
	fmt.Printf("HID: 0x")
	fmt.Printf("%x\n", HID[:])
	fmt.Printf("HTID: 0x")
	fmt.Printf("%x\n", HTID[:])

	// Destroy Y2
	defer CleanMemory(Y2[:])
	// Destroy E
	defer CleanMemory(E[:])
	// Destroy F
	defer CleanMemory(F[:])

	if rtn != 0 {
		fmt.Printf("Authentication failed Error Code %d\n", rtn)
		err := Kangaroo_BN254(E[:], F[:])
		if err != 0 {
			fmt.Printf("PIN Error %d\n", err)
		}
		return
	} else {
		fmt.Printf("Authenticated ID: %s \n", IDstr)
	}

	// send T=w.ID to client
	var W [PGS_BN254]byte
	fmt.Printf("W: 0x")
	fmt.Printf("%x\n", W[:])
	rtn, WOut, T := GetG1Multiple_BN254(&rng, 0, W[:], HTID[:])
	fmt.Printf("WOut: 0x")
	fmt.Printf("%x\n", WOut[:])
	fmt.Printf("T: 0x")
	fmt.Printf("%x\n", T[:])

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
	fmt.Printf("Server Key =  0x")
	fmt.Printf("%x\n", AES_KEY_SERVER[:])

	// Destroy AES_KEY_SERVER
	defer CleanMemory(AES_KEY_SERVER[:])

	rtn, AES_KEY_CLIENT := ClientKey_BN254(HASH_TYPE_MPIN, PIN2, G1[:], G2[:], ROut[:], XOut[:], HM[:], T[:])
	fmt.Printf("Client Key =  0x")
	fmt.Printf("%x\n", AES_KEY_CLIENT[:])

	// Destroy AES_KEY_CLIENT
	defer CleanMemory(AES_KEY_CLIENT[:])

	//////   Server   //////

	// Initialization vector
	IV := GenerateRandomByte(&rng, 12)
	fmt.Printf("IV: 0x")
	fmt.Printf("%x\n", IV[:])

	// Destroy IV
	defer CleanMemory(IV[:])

	// header
	HEADER := GenerateRandomByte(&rng, 16)
	fmt.Printf("HEADER: 0x")
	fmt.Printf("%x\n", HEADER[:])

	// Destroy HEADER
	defer CleanMemory(HEADER[:])

	// Input plaintext
	plaintextStr := "A test message"
	PLAINTEXT1 := []byte(plaintextStr)
	fmt.Printf("String to encrypt: %s \n", plaintextStr)
	fmt.Printf("PLAINTEXT1: 0x")
	fmt.Printf("%x\n", PLAINTEXT1[:])

	// Destroy PLAINTEXT1
	defer CleanMemory(PLAINTEXT1[:])

	// AES-GCM Encryption
	CIPHERTEXT, TAG1, err := AesGcmEncrypt(AES_KEY_SERVER[:], IV[:], HEADER[:], PLAINTEXT1[:])
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("CIPHERTEXT:  0x")
	fmt.Printf("%x\n", CIPHERTEXT[:])
	fmt.Printf("TAG1:  0x")
	fmt.Printf("%x\n", TAG1[:])

	// Destroy CIPHERTEXT
	defer CleanMemory(CIPHERTEXT[:])
	// Destroy TAG1
	defer CleanMemory(TAG1[:])

	// Send IV, HEADER, CIPHERTEXT and TAG1 to client

	// AES-GCM Decryption
	PLAINTEXT2, TAG2, err := AesGcmDecrypt(AES_KEY_CLIENT[:], IV[:], HEADER[:], CIPHERTEXT[:])
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("PLAINTEXT2:  0x")
	fmt.Printf("%x\n", PLAINTEXT2[:])
	fmt.Printf("TAG2:  0x")
	fmt.Printf("%x\n", TAG2[:])
	fmt.Printf("Decrypted string: %s \n", string(PLAINTEXT2))

	// Destroy PLAINTEXT2
	defer CleanMemory(PLAINTEXT2[:])
	// Destroy TAG2
	defer CleanMemory(TAG2[:])
}

// ExampleMPinTwoPass is example for MPin two pass
func ExampleMPinTwoPass() {
	HASH_TYPE_MPIN := SHA256

	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)
	fmt.Printf("ID: ")
	fmt.Printf("%x\n\n", ID)

	// Epoch time in days
	date := Today()

	// PIN variable to create token
	PIN1 := -1
	// PIN variable to authenticate
	PIN2 := -1

	// Seed value for Random Number Generator
	seedHex := "ac4509d6"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := CreateCSPRNG(seed)

	// Generate Master Secret Share 1
	rtn, MS1 := RandomGenerate_BN254(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate_BN254 Error:", rtn)
		return
	}
	fmt.Printf("MS1: 0x")
	fmt.Printf("%x\n", MS1[:])

	// Destroy MS1
	defer CleanMemory(MS1[:])

	// Generate Master Secret Share 2
	rtn, MS2 := RandomGenerate_BN254(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate_BN254 Error:", rtn)
		return
	}
	fmt.Printf("MS2: 0x")
	fmt.Printf("%x\n", MS2[:])

	// Destroy MS2
	defer CleanMemory(MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := HashId(HASH_TYPE_MPIN, PFS_BN254, ID)

	// Generate server secret share 1
	rtn, SS1 := GetServerSecret_BN254(MS1[:])
	if rtn != 0 {
		fmt.Println("GetServerSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("SS1: 0x")
	fmt.Printf("%x\n", SS1[:])

	// Destroy SS1
	defer CleanMemory(SS1[:])

	// Generate server secret share 2
	rtn, SS2 := GetServerSecret_BN254(MS2[:])
	if rtn != 0 {
		fmt.Println("GetServerSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("SS2: 0x")
	fmt.Printf("%x\n", SS2[:])

	// Destroy SS2
	defer CleanMemory(SS2[:])

	// Combine server secret shares
	rtn, SS := RecombineG2_BN254(SS1[:], SS2[:])
	if rtn != 0 {
		fmt.Println("RecombineG2_BN254(SS1, SS2) Error:", rtn)
		return
	}
	fmt.Printf("SS: 0x")
	fmt.Printf("%x\n", SS[:])

	// Destroy SS
	defer CleanMemory(SS[:])

	// Generate client secret share 1
	rtn, CS1 := GetClientSecret_BN254(MS1[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret Share CS1: 0x")
	fmt.Printf("%x\n", CS1[:])

	// Destroy CS1
	defer CleanMemory(CS1[:])

	// Generate client secret share 2
	rtn, CS2 := GetClientSecret_BN254(MS2[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientSecret_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret Share CS2: 0x")
	fmt.Printf("%x\n", CS2[:])

	// Destroy CS2
	defer CleanMemory(CS2[:])

	// Combine client secret shares
	CS := make([]byte, G1S_BN254)
	rtn, CS = RecombineG1_BN254(CS1[:], CS2[:])
	if rtn != 0 {
		fmt.Println("RecombineG1_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret CS: 0x")
	fmt.Printf("%x\n", CS[:])

	// Destroy CS
	defer CleanMemory(CS[:])

	// Generate time permit share 1
	rtn, TP1 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS1[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientPermit_BN254 Error:", rtn)
		return
	}
	fmt.Printf("TP1: 0x")
	fmt.Printf("%x\n", TP1[:])

	// Destroy TP1
	defer CleanMemory(TP1[:])

	// Generate time permit share 2
	rtn, TP2 := GetClientPermit_BN254(HASH_TYPE_MPIN, date, MS2[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientPermit_BN254 Error:", rtn)
		return
	}
	fmt.Printf("TP2: 0x")
	fmt.Printf("%x\n", TP2[:])

	// Destroy TP2
	defer CleanMemory(TP2[:])

	// Combine time permit shares
	rtn, TP := RecombineG1_BN254(TP1[:], TP2[:])
	if rtn != 0 {
		fmt.Println("RecombineG1_BN254(TP1, TP2) Error:", rtn)
		return
	}

	// Destroy TP
	defer CleanMemory(TP[:])

	// Client extracts PIN1 from secret to create Token
	for PIN1 < 0 {
		fmt.Printf("Please enter PIN to create token: ")
		fmt.Scan(&PIN1)
	}

	rtn, TOKEN := ExtractPIN_BN254(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: EXTRACT_PIN rtn: %d\n", rtn)
		return
	}
	fmt.Printf("Client Token TK: 0x")
	fmt.Printf("%x\n", TOKEN[:])

	// Destroy TOKEN
	defer CleanMemory(TOKEN[:])

	//////   Client   //////

	for PIN2 < 0 {
		fmt.Printf("Please enter PIN to authenticate: ")
		fmt.Scan(&PIN2)
	}

	////// Client Pass 1 //////
	// Send U and UT to server
	var X [PGS_BN254]byte
	fmt.Printf("X: 0x")
	fmt.Printf("%x\n", X[:])
	rtn, XOut, SEC, U, UT := Client1_BN254(HASH_TYPE_MPIN, date, ID, &rng, X[:], PIN2, TOKEN[:], TP[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: CLIENT rtn: %d\n", rtn)
		return
	}
	fmt.Printf("XOut: 0x")
	fmt.Printf("%x\n", XOut[:])

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
	rtn, Y := RandomGenerate_BN254(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate_BN254 Error:", rtn)
		return
	}
	fmt.Printf("Y: 0x")
	fmt.Printf("%x\n", Y[:])

	// Destroy Y
	defer CleanMemory(Y[:])

	/* Client Second Pass: Inputs Client secret SEC, x and y. Outputs -(x+y)*SEC */
	rtn, V := Client2_BN254(XOut[:], Y[:], SEC[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: CLIENT_2 rtn: %d\n", rtn)
	}

	// Destroy V
	defer CleanMemory(V[:])

	/* Server Second Pass. Inputs hashed client id, random Y, -(x+y)*SEC, xID and xCID and Server secret SST. E and F help Kangaroo_BN254s to find error. */
	/* If PIN error not required, set E and F = null */

	rtn, E, F := Server2_BN254(date, HID[:], HTID[:], nil, Y[:], SS[:], U[:], UT[:], V[:], true)
	if rtn != 0 {
		fmt.Printf("FAILURE: Server2 rtn: %d\n", rtn)
	}
	fmt.Printf("HID: 0x")
	fmt.Printf("%x\n", HID[:])
	fmt.Printf("HTID: 0x")
	fmt.Printf("%x\n", HTID[:])

	if rtn != 0 {
		fmt.Printf("Authentication failed Error Code %d\n", rtn)
		err := Kangaroo_BN254(E[:], F[:])
		if err != 0 {
			fmt.Printf("PIN Error %d\n", err)
		}
		return
	}

	if rtn != 0 {
		fmt.Printf("Authentication failed Error Code %d\n", rtn)
		return
	} else {
		fmt.Printf("Authenticated ID: %s \n", IDstr)
	}
}
