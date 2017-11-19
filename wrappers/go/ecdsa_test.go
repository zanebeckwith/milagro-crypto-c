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
)

// ExampleECDSA is example for ECDSA
func ExampleECDSA() {

	var rtn int

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}

	rng := CreateCSPRNG(seed)

	// Set PassPhrase
	PassPhraseStr := "AlicePassPhrase"
	PassPhrase := []byte(PassPhraseStr)

	// Set Salt
	SaltStr := "aabbccddee"
	Salt := []byte(SaltStr)

	// Generate ECC Private Key
	PrivKey := PBKDF2(SHA256, PassPhrase[:], Salt[:], 1000, EGS_BN254)

	// Destroy Private Key
	defer CleanMemory(PrivKey[:])
	// Destroy Salt
	defer CleanMemory(Salt[:])
	// Destroy Passphrase
	defer CleanMemory(PassPhrase[:])

	fmt.Printf("private key: 0x%x\n", PrivKey[:])

	// Generate ECC Key Pair
	rtn, PrivKey, PubKey := ECPKeyPairGenerate_BN254(nil, PrivKey)
	if rtn != 0 {
		log.Fatalf("error generating ECC key pair: %v", rtn)
	}
	fmt.Printf("public key: 0x%x\n", PubKey[:])

	// Validate ECC Public Key
	rtn = ECPPublicKeyValidate_BN254(1, PubKey[:])
	if rtn != 0 {
		log.Fatalf("error validating public key: %v", rtn)
	}

	// Message to sign
	MESSAGEstr := "Hello World\n"
	MESSAGE := []byte(MESSAGEstr)
	fmt.Printf("message: 0x%x\n", MESSAGE[:])

	rtn, C, D := ECPSpDsa_BN254(SHA256, &rng, nil, PrivKey[:], MESSAGE[:])
	if rtn != 0 {
		log.Fatalf("error generating ECDSA signature: %v", rtn)
	}
	// signed message pair
	fmt.Printf("C: 0x%x\n", C[:])
	fmt.Printf("D: 0x%x\n", D[:])

	// Verify Message
	rtn = ECPVpDsa_BN254(SHA256, PubKey[:], MESSAGE[:], C[:], D[:])
	if rtn != 0 {
		log.Fatalf("error validating ECDSA signature: %v", rtn)
	}

	// Output:
	// private key: 0x53c9d164e865ceaeb063e5474a212083cf3065616d59b1373c4afadcdbf3c048
	// public key: 0x04236bd1beb8ec954feb10fc087c4dd5b44a9049ea432231d634b6d97d4a71607e0bd6a9526d7ac191ed5771b233d95ab52d21a7a970fbf7d5bf32276da2bde51e
	// message: 0x48656c6c6f20576f726c640a
	// C: 0x1f0892879ef1bd6a1fdf901c41c615464f5cbd4519e1d24c0435f24990f6ec21
	// D: 0x0e1040ae10d68e580d525008b987da99b02d8aace2cbf8ce29a8e630a8d4ef5b
}

// ExampleECDSARandom is example for ECDSA
func ExampleECDSARandom() {

	var rtn int

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}

	rng := CreateCSPRNG(seed)

	// Generate ECC Key Pair
	rtn, PrivKey, PubKey := ECPKeyPairGenerate_BN254(&rng, nil)
	if rtn != 0 {
		log.Fatalf("error generating ECC key pair: %v", rtn)
	}

	// Destroy Private Key
	defer CleanMemory(PrivKey[:])

	fmt.Printf("private key: 0x%x\n", PrivKey[:])
	fmt.Printf("public key: 0x%x\n", PubKey[:])

	// Validate ECC Public Key
	rtn = ECPPublicKeyValidate_BN254(1, PubKey[:])
	if rtn != 0 {
		log.Fatalf("error validating ECC public key: %v", rtn)
	}

	// Message to sign
	MESSAGEstr := "Hello World\n"
	MESSAGE := []byte(MESSAGEstr)
	fmt.Printf("message: 0x%x\n", MESSAGE[:])

	// Sign Message
	rtn, C, D := ECPSpDsa_BN254(SHA256, &rng, nil, PrivKey[:], MESSAGE[:])
	if rtn != 0 {
		log.Fatalf("error generating ECDSA signature: %v", rtn)
	}
	// signed message pair
	fmt.Printf("C: 0x%x\n", C[:])
	fmt.Printf("D: 0x%x\n", D[:])

	// Verify Message
	rtn = ECPVpDsa_BN254(SHA256, PubKey[:], MESSAGE[:], C[:], D[:])
	if rtn != 0 {
		log.Fatalf("error verifying ECDSA signature: %v", rtn)
	}

	// Output:
	// private key: 0x1ddf6798fba82aa24d588f4964960b363613e95834fad705ca2ae4b0ffee8f2d
	// public key: 0x041f0892879ef1bd6a1fdf901c41c615464f5cbd4519e1d24c0435f24990f6ec2124e7de5dc4df24fea78601ca4261dc5e10b4bed15c05ebee76dc6e2fb76dae78
	// message: 0x48656c6c6f20576f726c640a
	// C: 0x139243559562fb36b1393b9360cb8f658f5691a1c6830b624b39621cacdb991e
	// D: 0x0441aec7e98ddf9db123a07e3a11309abb074b7da6e635ee36732f5b4eca96c0
}
