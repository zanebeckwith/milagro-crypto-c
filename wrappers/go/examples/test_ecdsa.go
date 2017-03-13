/**
 * @file test_dsa.go
 * @author Alessandro Budroni
 * @brief ECDSA test
 *
 * LICENSE
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

 package main

import (
	"encoding/hex"
	"fmt"

	"github.com/miracl/amcl-go-wrapper"
)

func main() {

	var rtn int;

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}

	rng := amcl.CreateCSPRNG(seed)

	// Set PassPhrase
	PassPhraseStr := "AlicePassPhrase"
	PassPhrase := []byte(PassPhraseStr)

	fmt.Printf("PassPhrase: ")
	fmt.Printf("%s\n\n", PassPhrase[:])

	// Set Salt
	SaltStr := "aabbccddee"
	Salt := []byte(SaltStr)

	fmt.Printf("Salt: ")
	fmt.Printf("%s\n\n", Salt[:])


	// Generating public/private key pair
	fmt.Printf("Generating public/private key pair\n")

	// Generate ECC Private Key
	PrivKey := PBKDF2(SHA256, PassPhrase[:], Salt[:], 1000, EGS)

	fmt.Printf("Private Key: 0x")
	fmt.Printf("%x\n\n", PrivKey[:])

	// Generate ECC Key Pair
	rtn, PrivKey, PubKey := ECPKeyPairGeneate(nil, PrivKey)
	assert.Equal(t, rtn, 0, "Error - Generating ECC Key Pair")

	fmt.Printf("Public Key: 0x")
	fmt.Printf("%x\n\n", PubKey[:])







	// NOTE - use the following only for testing
	rtn = int(amcl.OctetComp(/**/,/**/))
	if rtn != 1 {
		fmt.Println("Error - /**/:", rtn)
		return
	}


}