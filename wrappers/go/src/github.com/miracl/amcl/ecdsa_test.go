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
	"testing"

	"github.com/miracl/amcl/wrap"
)

func TestECDSA(t *testing.T) {
	seed, err := hex.DecodeString("9e8b4178790cd57a5761c4a6f164ba72")
	if err != nil {
		t.Fatal(err)
	}
	rng := wrap.NewRand(seed)

	testCases := []struct {
		curve             string
		pbkdfKeyLen       int
		genKey            func(R *wrap.Rand, s []byte) (sResult []byte, W []byte, err error)
		genSeed           []byte
		ecpPubKeyValidate func(W []byte) (err error)
		sign              func(h int, R *wrap.Rand, k []byte, s []byte, M []byte) (c []byte, d []byte, err error)
		verify            func(h int, W []byte, M []byte, c []byte, d []byte) (err error)
	}{
		{
			curve:             "BLS383",
			pbkdfKeyLen:       wrap.EGS_BLS383,
			genKey:            ECPKeyPairGenerate_BLS383,
			ecpPubKeyValidate: ECPPublicKeyValidate_BLS383,
			sign:              ECPSpDsa_BLS383,
			verify:            ECPVpDsa_BLS383,
		},
		{
			curve:             "BN254",
			pbkdfKeyLen:       wrap.EGS_BN254,
			genKey:            ECPKeyPairGenerate_BN254,
			ecpPubKeyValidate: ECPPublicKeyValidate_BN254,
			sign:              ECPSpDsa_BN254,
			verify:            ECPVpDsa_BN254,
		},
		{
			curve:             "BN254CX",
			pbkdfKeyLen:       wrap.EGS_BN254CX,
			genKey:            ECPKeyPairGenerate_BN254CX,
			ecpPubKeyValidate: ECPPublicKeyValidate_BN254CX,
			sign:              ECPSpDsa_BN254CX,
			verify:            ECPVpDsa_BN254CX,
		},
		{
			curve:             "ED25519",
			pbkdfKeyLen:       wrap.EGS_ED25519,
			genKey:            ECPKeyPairGenerate_ED25519,
			ecpPubKeyValidate: ECPPublicKeyValidate_ED25519,
			sign:              ECPSpDsa_ED25519,
			verify:            ECPVpDsa_ED25519,
		},
		{
			curve:             "GOLDILOCKS",
			pbkdfKeyLen:       wrap.EGS_GOLDILOCKS,
			genKey:            ECPKeyPairGenerate_GOLDILOCKS,
			ecpPubKeyValidate: ECPPublicKeyValidate_GOLDILOCKS,
			sign:              ECPSpDsa_GOLDILOCKS,
			verify:            ECPVpDsa_GOLDILOCKS,
		},
		{
			curve:             "NIST256",
			pbkdfKeyLen:       wrap.EGS_NIST256,
			genKey:            ECPKeyPairGenerate_NIST256,
			ecpPubKeyValidate: ECPPublicKeyValidate_NIST256,
			sign:              ECPSpDsa_NIST256,
			verify:            ECPVpDsa_NIST256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.curve, func(t *testing.T) {

			PassPhraseStr := "AlicePassPhrase"
			PassPhrase := []byte(PassPhraseStr)

			SaltStr := "aabbccddee"
			Salt := []byte(SaltStr)

			// Generate ECC Private Key
			PrivKey := wrap.PBKDF2(wrap.SHA256, PassPhrase[:], Salt[:], 1000, tc.pbkdfKeyLen)

			// Destroy Private Key
			defer CleanMemory(PrivKey[:])

			// Generate ECC Key Pair
			PrivKey, PubKey, err := tc.genKey(nil, PrivKey)
			if err != nil {
				t.Errorf("ECC key pair generation failed; rtn=%v", err)
			}

			// Validate ECC Public Key
			err = tc.ecpPubKeyValidate(PubKey[:])
			if err != nil {
				t.Errorf("ECC public key is invalid; rtn=%v", err)
			}

			// Message to sign
			MESSAGEstr := "Hello World\n"
			MESSAGE := []byte(MESSAGEstr)

			// Sign Message
			C, D, err := tc.sign(wrap.SHA256, rng, nil, PrivKey[:], MESSAGE[:])
			if err != nil {
				t.Errorf("ECDSA signature sailed; rtn=%v", err)
			}

			// Verify Message
			err = tc.verify(wrap.SHA256, PubKey[:], MESSAGE[:], C[:], D[:])
			if err != nil {
				t.Errorf("ECDSA verification failed; rtn=%v", err)
			}
		})
	}
}

func TestECDSARandom(t *testing.T) {
	seed, err := hex.DecodeString("9e8b4178790cd57a5761c4a6f164ba72")
	if err != nil {
		t.Fatal(err)
	}
	rng := wrap.NewRand(seed)

	testCases := []struct {
		curve             string
		genKey            func(R *wrap.Rand, s []byte) (sResult []byte, W []byte, err error)
		genSeed           []byte
		ecpPubKeyValidate func(W []byte) (err error)
		sign              func(h int, R *wrap.Rand, k []byte, s []byte, M []byte) (c []byte, d []byte, err error)
		verify            func(h int, W []byte, M []byte, c []byte, d []byte) (err error)
	}{
		{
			curve:             "BLS383",
			genKey:            ECPKeyPairGenerate_BLS383,
			ecpPubKeyValidate: ECPPublicKeyValidate_BLS383,
			sign:              ECPSpDsa_BLS383,
			verify:            ECPVpDsa_BLS383,
		},
		{
			curve:             "BN254",
			genKey:            ECPKeyPairGenerate_BN254,
			ecpPubKeyValidate: ECPPublicKeyValidate_BN254,
			sign:              ECPSpDsa_BN254,
			verify:            ECPVpDsa_BN254,
		},
		{
			curve:             "BN254CX",
			genKey:            ECPKeyPairGenerate_BN254CX,
			ecpPubKeyValidate: ECPPublicKeyValidate_BN254CX,
			sign:              ECPSpDsa_BN254CX,
			verify:            ECPVpDsa_BN254CX,
		},
		{
			curve:             "ED25519",
			genKey:            ECPKeyPairGenerate_ED25519,
			ecpPubKeyValidate: ECPPublicKeyValidate_ED25519,
			sign:              ECPSpDsa_ED25519,
			verify:            ECPVpDsa_ED25519,
		},
		{
			curve:             "GOLDILOCKS",
			genKey:            ECPKeyPairGenerate_GOLDILOCKS,
			ecpPubKeyValidate: ECPPublicKeyValidate_GOLDILOCKS,
			sign:              ECPSpDsa_GOLDILOCKS,
			verify:            ECPVpDsa_GOLDILOCKS,
		},
		{
			curve:             "NIST256",
			genKey:            ECPKeyPairGenerate_NIST256,
			ecpPubKeyValidate: ECPPublicKeyValidate_NIST256,
			sign:              ECPSpDsa_NIST256,
			verify:            ECPVpDsa_NIST256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.curve, func(t *testing.T) {

			// Generate ECC Key Pair
			PrivKey, PubKey, err := tc.genKey(rng, nil)
			if err != nil {
				t.Errorf("ECC key pair generation failed; rtn=%v", err)
			}

			// Destroy Private Key
			defer CleanMemory(PrivKey[:])

			// Validate ECC Public Key
			err = tc.ecpPubKeyValidate(PubKey[:])
			if err != nil {
				t.Errorf("ECC Public Key is invalid; rtn=%v", err)
			}

			// Message to sign
			MESSAGEstr := "Hello World\n"
			MESSAGE := []byte(MESSAGEstr)

			// Sign Message
			C, D, err := tc.sign(wrap.SHA256, rng, nil, PrivKey[:], MESSAGE[:])
			if err != nil {
				t.Errorf("ECDSA signature failed; rtn=%v", err)
			}

			// Verify Message
			err = tc.verify(wrap.SHA256, PubKey[:], MESSAGE[:], C[:], D[:])
			if err != nil {
				t.Errorf("ECDSA verification failed; rtn=%v", err)
			}
		})
	}
}

// ExampleECDSA is example for ECDSA
func ExampleECDSA() {

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}

	rng := wrap.NewRand(seed)

	// Set PassPhrase
	PassPhraseStr := "AlicePassPhrase"
	PassPhrase := []byte(PassPhraseStr)

	// Set Salt
	SaltStr := "aabbccddee"
	Salt := []byte(SaltStr)

	// Generate ECC Private Key
	PrivKey := wrap.PBKDF2(wrap.SHA256, PassPhrase[:], Salt[:], 1000, wrap.EGS_BN254)

	// Destroy Private Key
	defer CleanMemory(PrivKey[:])
	// Destroy Salt
	defer CleanMemory(Salt[:])
	// Destroy Passphrase
	defer CleanMemory(PassPhrase[:])

	fmt.Printf("private key: 0x%x\n", PrivKey[:])

	// Generate ECC Key Pair
	PrivKey, PubKey, err := ECPKeyPairGenerate_BN254(nil, PrivKey)
	if err != nil {
		log.Fatalf("error generating ECC key pair: %v", err)
	}
	fmt.Printf("public key: 0x%x\n", PubKey[:])

	// Validate ECC Public Key
	err = ECPPublicKeyValidate_BN254(PubKey[:])
	if err != nil {
		log.Fatalf("error validating public key: %v", err)
	}

	// Message to sign
	MESSAGEstr := "Hello World\n"
	MESSAGE := []byte(MESSAGEstr)
	fmt.Printf("message: 0x%x\n", MESSAGE[:])

	C, D, err := ECPSpDsa_BN254(wrap.SHA256, rng, nil, PrivKey[:], MESSAGE[:])
	if err != nil {
		log.Fatalf("error generating ECDSA signature: %v", err)
	}
	// signed message pair
	fmt.Printf("C: 0x%x\n", C[:])
	fmt.Printf("D: 0x%x\n", D[:])

	// Verify Message
	err = ECPVpDsa_BN254(wrap.SHA256, PubKey[:], MESSAGE[:], C[:], D[:])
	if err != nil {
		log.Fatalf("error validating ECDSA signature: %v", err)
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

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}

	rng := wrap.NewRand(seed)

	// Generate ECC Key Pair
	PrivKey, PubKey, err := ECPKeyPairGenerate_BN254(rng, nil)
	if err != nil {
		log.Fatalf("error generating ECC key pair: %v", err)
	}

	// Destroy Private Key
	defer CleanMemory(PrivKey[:])

	fmt.Printf("private key: 0x%x\n", PrivKey[:])
	fmt.Printf("public key: 0x%x\n", PubKey[:])

	// Validate ECC Public Key
	err = ECPPublicKeyValidate_BN254(PubKey[:])
	if err != nil {
		log.Fatalf("error validating ECC public key: %v", err)
	}

	// Message to sign
	MESSAGEstr := "Hello World\n"
	MESSAGE := []byte(MESSAGEstr)
	fmt.Printf("message: 0x%x\n", MESSAGE[:])

	// Sign Message
	C, D, err := ECPSpDsa_BN254(wrap.SHA256, rng, nil, PrivKey[:], MESSAGE[:])
	if err != nil {
		log.Fatalf("error generating ECDSA signature: %v", err)
	}
	// signed message pair
	fmt.Printf("C: 0x%x\n", C[:])
	fmt.Printf("D: 0x%x\n", D[:])

	// Verify Message
	err = ECPVpDsa_BN254(wrap.SHA256, PubKey[:], MESSAGE[:], C[:], D[:])
	if err != nil {
		log.Fatalf("error verifying ECDSA signature: %v", err)
	}

	// Output:
	// private key: 0x1ddf6798fba82aa24d588f4964960b363613e95834fad705ca2ae4b0ffee8f2d
	// public key: 0x041f0892879ef1bd6a1fdf901c41c615464f5cbd4519e1d24c0435f24990f6ec2124e7de5dc4df24fea78601ca4261dc5e10b4bed15c05ebee76dc6e2fb76dae78
	// message: 0x48656c6c6f20576f726c640a
	// C: 0x139243559562fb36b1393b9360cb8f658f5691a1c6830b624b39621cacdb991e
	// D: 0x0441aec7e98ddf9db123a07e3a11309abb074b7da6e635ee36732f5b4eca96c0
}
