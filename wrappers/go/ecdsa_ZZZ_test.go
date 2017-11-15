/**
 * @file ecsa_test.go
 * @author Alessandro Budroni
 * @brief ECDSA Wrappers tests
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

package amcl

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestECDSARandom_ZZZ(t *testing.T) {

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}

	rng := CreateCSPRNG(seed)

	// Generate ECC Key Pair
	rtn, PrivKey, PubKey := ECPKeyPairGenerate_ZZZ(&rng, nil)
	if rtn != 0 {
		t.Errorf("ECC key pair generation failed; rtn=%v", rtn)
	}

	// Destroy Private Key
	defer CleanMemory(PrivKey[:])

	// Validate ECC Public Key
	rtn = ECPPublicKeyValidate_ZZZ(1, PubKey[:])
	if rtn != 0 {
		t.Errorf("ECC Public Key is invalid; rtn=%v", rtn)
	}

	// Message to sign
	MESSAGEstr := "Hello World\n"
	MESSAGE := []byte(MESSAGEstr)

	// Sign Message
	rtn, C, D := ECPSpDsa_ZZZ(SHA256, &rng, nil, PrivKey[:], MESSAGE[:])
	if rtn != 0 {
		t.Errorf("ECDSA signature failed; rtn=%v", rtn)
	}

	// Verify Message
	rtn = ECPVpDsa_ZZZ(SHA256, PubKey[:], MESSAGE[:], C[:], D[:])
	if rtn != 0 {
		t.Errorf("ECDSA verification failed; rtn=%v", rtn)
	}

}

func TestECDSA_ZZZ(t *testing.T) {

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}

	rng := CreateCSPRNG(seed)

	PassPhraseStr := "AlicePassPhrase"
	PassPhrase := []byte(PassPhraseStr)

	SaltStr := "aabbccddee"
	Salt := []byte(SaltStr)

	// Generate ECC Private Key
	PrivKey := PBKDF2(SHA256, PassPhrase[:], Salt[:], 1000, EGS_ZZZ)

	// Destroy Private Key
	defer CleanMemory(PrivKey[:])

	// Generate ECC Key Pair
	rtn, PrivKey, PubKey := ECPKeyPairGenerate_ZZZ(nil, PrivKey)
	if rtn != 0 {
		t.Errorf("ECC key pair generation failed; rtn=%v", rtn)
	}

	// Validate ECC Public Key
	rtn = ECPPublicKeyValidate_ZZZ(1, PubKey[:])
	if rtn != 0 {
		t.Errorf("ECC public key is invalid; rtn=%v", rtn)
	}

	// Message to sign
	MESSAGEstr := "Hello World\n"
	MESSAGE := []byte(MESSAGEstr)

	// Sign Message
	rtn, C, D := ECPSpDsa_ZZZ(SHA256, &rng, nil, PrivKey[:], MESSAGE[:])
	if rtn != 0 {
		t.Errorf("ECDSA signature sailed; rtn=%v", rtn)
	}

	// Verify Message
	rtn = ECPVpDsa_ZZZ(SHA256, PubKey[:], MESSAGE[:], C[:], D[:])
	if rtn != 0 {
		t.Errorf("ECDSA verification failed; rtn=%v", rtn)
	}

}
