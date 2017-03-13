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

package main

import (
	"encoding/hex"
	"fmt"

	"github.com/miracl/amcl-go-wrapper"
)

var HASH_TYPE_MPIN = amcl.SHA256

func main() {
	// Assign the End-User an ID
	IDstr := "testUser@miracl.com"
	ID := []byte(IDstr)
	fmt.Printf("ID: ")
	fmt.Printf("%x\n\n", ID)

	// Epoch time in days
	date := amcl.Today()
	fmt.Println("date: ", date)

	// Epoch time in seconds
	timeValue := amcl.GetTime()
	fmt.Println("timeValue: ", timeValue)

	// PIN variable to create token
	PIN1 := -1
	// PIN variable to authenticate
	PIN2 := -1

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := amcl.CreateCSPRNG(seed)

	// Message to sign
	var MESSAGE []byte
	// MESSAGE := []byte("test sign message")

	// Generate Master Secret Share 1
	rtn, MS1 := amcl.RandomGenerate(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate Error:", rtn)
		return
	}
	fmt.Printf("MS1: 0x")
	fmt.Printf("%x\n", MS1[:])

	// Generate Master Secret Share 2
	rtn, MS2 := amcl.RandomGenerate(&rng)
	if rtn != 0 {
		fmt.Println("RandomGenerate Error:", rtn)
		return
	}
	fmt.Printf("MS2: 0x")
	fmt.Printf("%x\n", MS2[:])

	// Either Client or TA calculates Hash(ID)
	HCID := amcl.HashId(HASH_TYPE_MPIN, ID)

	// Generate server secret share 1
	rtn, SS1 := amcl.GetServerSecret(MS1[:])
	if rtn != 0 {
		fmt.Println("GetServerSecret Error:", rtn)
		return
	}
	fmt.Printf("SS1: 0x")
	fmt.Printf("%x\n", SS1[:])

	// Generate server secret share 2
	rtn, SS2 := amcl.GetServerSecret(MS2[:])
	if rtn != 0 {
		fmt.Println("GetServerSecret Error:", rtn)
		return
	}
	fmt.Printf("SS2: 0x")
	fmt.Printf("%x\n", SS2[:])

	// Combine server secret shares
	rtn, SS := amcl.RecombineG2(SS1[:], SS2[:])
	if rtn != 0 {
		fmt.Println("RecombineG2(SS1, SS2) Error:", rtn)
		return
	}
	fmt.Printf("SS: 0x")
	fmt.Printf("%x\n", SS[:])

	// Generate client secret share 1
	rtn, CS1 := amcl.GetClientSecret(MS1[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientSecret Error:", rtn)
		return
	}
	fmt.Printf("Client Secret Share CS1: 0x")
	fmt.Printf("%x\n", CS1[:])

	// Generate client secret share 2
	rtn, CS2 := amcl.GetClientSecret(MS2[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientSecret Error:", rtn)
		return
	}
	fmt.Printf("Client Secret Share CS2: 0x")
	fmt.Printf("%x\n", CS2[:])

	// Combine client secret shares
	CS := make([]byte, amcl.G1S)
	rtn, CS = amcl.RecombineG1(CS1[:], CS2[:])
	if rtn != 0 {
		fmt.Println("RecombineG1 Error:", rtn)
		return
	}
	fmt.Printf("Client Secret CS: 0x")
	fmt.Printf("%x\n", CS[:])

	// Generate time permit share 1
	rtn, TP1 := amcl.GetClientPermit(HASH_TYPE_MPIN, date, MS1[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientPermit Error:", rtn)
		return
	}
	fmt.Printf("TP1: 0x")
	fmt.Printf("%x\n", TP1[:])

	// Generate time permit share 2
	rtn, TP2 := amcl.GetClientPermit(HASH_TYPE_MPIN, date, MS2[:], HCID)
	if rtn != 0 {
		fmt.Println("GetClientPermit Error:", rtn)
		return
	}
	fmt.Printf("TP2: 0x")
	fmt.Printf("%x\n", TP2[:])

	// Combine time permit shares
	rtn, TP := amcl.RecombineG1(TP1[:], TP2[:])
	if rtn != 0 {
		fmt.Println("RecombineG1(TP1, TP2) Error:", rtn)
		return
	}

	// Client extracts PIN1 from secret to create Token
	for PIN1 < 0 {
		fmt.Printf("Please enter PIN to create token: ")
		fmt.Scan(&PIN1)
	}

	rtn, TOKEN := amcl.ExtractPIN(HASH_TYPE_MPIN, ID[:], PIN1, CS[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: EXTRACT_PIN rtn: %d\n", rtn)
		return
	}
	fmt.Printf("Client Token TK: 0x")
	fmt.Printf("%x\n", TOKEN[:])

	//////   Client   //////

	// Precomputation
	rtn, G1, G2 := amcl.Precompute(TOKEN[:], HCID)
	if rtn != 0 {
		fmt.Println("Precompute(TOKEN[:], HCID) Error:", rtn)
		return
	}

	for PIN2 < 0 {
		fmt.Printf("Please enter PIN to authenticate: ")
		fmt.Scan(&PIN2)
	}

	// Send U, UT, V, timeValue and Message to server
	var X [amcl.PGS]byte
	fmt.Printf("X: 0x")
	fmt.Printf("%x\n", X[:])
	rtn, XOut, Y1, V, U, UT := amcl.Client(HASH_TYPE_MPIN, date, ID[:], &rng, X[:], PIN2, TOKEN[:], TP[:], MESSAGE[:], timeValue)
	if rtn != 0 {
		fmt.Printf("FAILURE: CLIENT rtn: %d\n", rtn)
		return
	}
	fmt.Printf("Y1: 0x")
	fmt.Printf("%x\n", Y1[:])
	fmt.Printf("XOut: 0x")
	fmt.Printf("%x\n", XOut[:])

	// Send Z=r.ID to Server
	var R [amcl.PGS]byte
	fmt.Printf("R: 0x")
	fmt.Printf("%x\n", R[:])
	rtn, ROut, Z := amcl.GetG1Multiple(&rng, 1, R[:], HCID[:])
	fmt.Printf("ROut: 0x")
	fmt.Printf("%x\n", ROut[:])

	//////   Server   //////
	rtn, HID, HTID, Y2, E, F := amcl.Server(HASH_TYPE_MPIN, date, timeValue, SS[:], U[:], UT[:], V[:], HCID[:], MESSAGE[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: SERVER rtn: %d\n", rtn)
	}
	fmt.Printf("Y2: 0x")
	fmt.Printf("%x\n", Y2[:])
	fmt.Printf("HID: 0x")
	fmt.Printf("%x\n", HID[:])
	fmt.Printf("HTID: 0x")
	fmt.Printf("%x\n", HTID[:])

	if rtn != 0 {
		fmt.Printf("Authentication failed Error Code %d\n", rtn)
		err := amcl.Kangaroo(E[:], F[:])
		if err != 0 {
			fmt.Printf("PIN Error %d\n", err)
		}
		return
	} else {
		fmt.Printf("Authenticated ID: %s \n", IDstr)
	}

	// send T=w.ID to client
	var W [amcl.PGS]byte
	fmt.Printf("W: 0x")
	fmt.Printf("%x\n", W[:])
	rtn, WOut, T := amcl.GetG1Multiple(&rng, 0, W[:], HTID[:])
	fmt.Printf("WOut: 0x")
	fmt.Printf("%x\n", WOut[:])
	fmt.Printf("T: 0x")
	fmt.Printf("%x\n", T[:])

	// Hash all values
	HM := amcl.HashAll(HASH_TYPE_MPIN, HCID[:], U[:], UT[:], Y2[:], V[:], Z[:], T[:])

	rtn, AES_KEY_SERVER := amcl.ServerKey(HASH_TYPE_MPIN, Z[:], SS[:], WOut[:], HM[:], HID[:], U[:], UT[:])
	fmt.Printf("Server Key =  0x")
	fmt.Printf("%x\n", AES_KEY_SERVER[:])

	rtn, AES_KEY_CLIENT := amcl.ClientKey(HASH_TYPE_MPIN, PIN2, G1[:], G2[:], ROut[:], XOut[:], HM[:], T[:])
	fmt.Printf("Client Key =  0x")
	fmt.Printf("%x\n", AES_KEY_CLIENT[:])

	//////   Server   //////

	// Initialization vector
	IV := amcl.GenerateRandomByte(&rng, 12)
	fmt.Printf("IV: 0x")
	fmt.Printf("%x\n", IV[:])

	// header
	HEADER := amcl.GenerateRandomByte(&rng, 16)
	fmt.Printf("HEADER: 0x")
	fmt.Printf("%x\n", HEADER[:])

	// Input plaintext
	plaintextStr := "A test message"
	PLAINTEXT1 := []byte(plaintextStr)
	fmt.Printf("String to encrypt: %s \n", plaintextStr)
	fmt.Printf("PLAINTEXT1: 0x")
	fmt.Printf("%x\n", PLAINTEXT1[:])

	// AES-GCM Encryption
	CIPHERTEXT, TAG1 := amcl.AesGcmEncrypt(AES_KEY_SERVER[:], IV[:], HEADER[:], PLAINTEXT1[:])
	fmt.Printf("CIPHERTEXT:  0x")
	fmt.Printf("%x\n", CIPHERTEXT[:])
	fmt.Printf("TAG1:  0x")
	fmt.Printf("%x\n", TAG1[:])

	// Send IV, HEADER, CIPHERTEXT and TAG1 to client

	// AES-GCM Decryption
	PLAINTEXT2, TAG2 := amcl.AesGcmDecrypt(AES_KEY_CLIENT[:], IV[:], HEADER[:], CIPHERTEXT[:])
	fmt.Printf("PLAINTEXT2:  0x")
	fmt.Printf("%x\n", PLAINTEXT2[:])
	fmt.Printf("TAG2:  0x")
	fmt.Printf("%x\n", TAG2[:])
	fmt.Printf("Decrypted string: %s \n", string(PLAINTEXT2))
}
