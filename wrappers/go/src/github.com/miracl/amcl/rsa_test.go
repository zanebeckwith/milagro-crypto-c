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
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/miracl/amcl/wrap"
)

func TestRSA(t *testing.T) {
	testCases := []struct {
		keySize     int
		hashType    int
		keyPairFunc func(RNG *wrap.Rand, e int32, P []byte, Q []byte) (wrap.RSAPrivateKey, wrap.RSAPublicKey)
		encryptFunc func(publicKey wrap.RSAPublicKey, F []byte) (G []byte)
		decryptFunc func(privateKey wrap.RSAPrivateKey, G []byte) (F []byte)
		keyKillFunc func(privateKey wrap.RSAPrivateKey)
	}{
		{
			keySize:     wrap.RFS_2048,
			hashType:    wrap.HASH_TYPE_RSA_2048,
			keyPairFunc: RSAKeyPair_2048,
			encryptFunc: RSAEncrypt_2048,
			decryptFunc: RSADecrypt_2048,
			keyKillFunc: RSAPrivateKeyKill_2048,
		},
		{
			keySize:     wrap.RFS_3072,
			hashType:    wrap.HASH_TYPE_RSA_3072,
			keyPairFunc: RSAKeyPair_3072,
			encryptFunc: RSAEncrypt_3072,
			decryptFunc: RSADecrypt_3072,
			keyKillFunc: RSAPrivateKeyKill_3072,
		},
		{
			keySize:     wrap.RFS_4096,
			hashType:    wrap.HASH_TYPE_RSA_4096,
			keyPairFunc: RSAKeyPair_4096,
			encryptFunc: RSAEncrypt_4096,
			decryptFunc: RSADecrypt_4096,
			keyKillFunc: RSAPrivateKeyKill_4096,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("KeySize%v", tc.keySize*8), func(t *testing.T) {
			// Seed value for Random Number Generator (RNG)
			seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
			seed, err := hex.DecodeString(seedHex)
			if err != nil {
				fmt.Println("Error decoding seed value")
				return
			}

			rng := wrap.NewRand(seed)

			// Message to encrypt
			MESSAGEstr := "Hello World\n"
			MESSAGE := []byte(MESSAGEstr)

			// Generating public/private key pair
			RSA_PrivKey, RSA_PubKey := tc.keyPairFunc(rng, 65537, nil, nil)

			// OAEP encode MESSAGE to e
			F, _ := OAEPencode(tc.hashType, MESSAGE, rng, nil, tc.keySize)

			// encrypt encoded MESSAGE
			G := tc.encryptFunc(RSA_PubKey, F[:])

			// decrypt encrypted MESSAGE
			ML := tc.decryptFunc(RSA_PrivKey, G[:])

			// OAEP decode MESSAGE
			Fgot, _ := OAEPdecode(tc.hashType, nil, ML[:])

			// destroy private key
			tc.keyKillFunc(RSA_PrivKey)

			if !bytes.Equal(Fgot, MESSAGE) {
				t.Errorf("OAEP decode failed; %v != %v", string(Fgot), MESSAGEstr)
			}
		})
	}
}

func TestRSASign(t *testing.T) {
	testCases := []struct {
		keySize     int
		hashType    int
		keyPairFunc func(RNG *wrap.Rand, e int32, P []byte, Q []byte) (wrap.RSAPrivateKey, wrap.RSAPublicKey)
		encryptFunc func(publicKey wrap.RSAPublicKey, F []byte) (G []byte)
		decryptFunc func(privateKey wrap.RSAPrivateKey, G []byte) (F []byte)
		keyKillFunc func(privateKey wrap.RSAPrivateKey)
	}{
		{
			keySize:     wrap.RFS_2048,
			hashType:    wrap.HASH_TYPE_RSA_2048,
			keyPairFunc: RSAKeyPair_2048,
			encryptFunc: RSAEncrypt_2048,
			decryptFunc: RSADecrypt_2048,
			keyKillFunc: RSAPrivateKeyKill_2048,
		},
		{
			keySize:     wrap.RFS_3072,
			hashType:    wrap.HASH_TYPE_RSA_3072,
			keyPairFunc: RSAKeyPair_3072,
			encryptFunc: RSAEncrypt_3072,
			decryptFunc: RSADecrypt_3072,
			keyKillFunc: RSAPrivateKeyKill_3072,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("KeySize%v", tc.keySize*8), func(t *testing.T) {
			// Seed value for Random Number Generator (RNG)
			seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
			seed, err := hex.DecodeString(seedHex)
			if err != nil {
				fmt.Println("Error decoding seed value")
				return
			}

			rng := wrap.NewRand(seed)

			// Generating public/private key pair
			RSA_PrivKey, RSA_PubKey := tc.keyPairFunc(rng, 65537, nil, nil)

			// Message to encrypt
			MESSAGEstr := "Hello World\n"
			MESSAGE := []byte(MESSAGEstr)

			// Signing message
			C, _ := PKCS15(tc.hashType, MESSAGE, tc.keySize)

			// create signature in S
			S := tc.decryptFunc(RSA_PrivKey, C[:])

			Cgot := tc.encryptFunc(RSA_PubKey, S[:])

			// destroy private key
			tc.keyKillFunc(RSA_PrivKey)

			if !bytes.Equal(Cgot, C) {
				t.Errorf("RSA encryption failed; %v != %v", Cgot, C)
			}
		})
	}
}

// ExampleRSAEncryption is example for RSA encryption and decryption
func ExampleRSAEncryption() {

	var rtn int

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}

	rng := wrap.NewRand(seed)

	// Message to encrypt
	MESSAGEstr := "Hello World"
	MESSAGE := []byte(MESSAGEstr)
	fmt.Printf("message: %s\n", MESSAGE[:])

	// Generating public/private key pair
	RSA_PrivKey, RSA_PubKey := RSAKeyPair_2048(rng, 65537, nil, nil)

	// OAEP encode MESSAGE to e
	F, err := OAEPencode(wrap.HASH_TYPE_RSA_2048, MESSAGE, rng, nil, wrap.RFS_2048)
	if err != nil {
		log.Println(err)
		log.Fatalf("OAEPencode error: %v", err)
	}

	fmt.Printf("encoded message: 0x%x\n", F[:])

	// encrypt encoded MESSAGE
	G := RSAEncrypt_2048(RSA_PubKey, F[:])
	fmt.Printf("encrypted message: 0x%x\n", G[:])

	// decrypt encrypted MESSAGE
	ML := RSADecrypt_2048(RSA_PrivKey, G[:])
	fmt.Printf("decrypted message: 0x%x\n", ML[:])

	// OAEP decode MESSAGE
	MESSAGEgot, err := OAEPdecode(wrap.HASH_TYPE_RSA_2048, nil, ML[:])
	if err != nil {
		log.Fatalf("OAEPdecode error: %v", err)
	}
	fmt.Printf("decoded message: %s\n", MESSAGEgot[:])

	// NOTE - use the following only for testing
	rtn = int(wrap.OctetComp(MESSAGE, MESSAGEgot))
	if rtn != 1 {
		log.Fatalf("message doesn't correspond to the expected one: %v", rtn)
	}

	// destroy private key
	RSAPrivateKeyKill_2048(RSA_PrivKey)

	// Output:
	// message: Hello World
	// encoded message: 0x00a8cf07c340a5d6b3e8e5625e3bf6006f12d70dd5296c0886568f23b56aaf52adca5497f9939f7994b53bf8b9d656a932373881ecd749e8692c8c0cd8c46205a5ed11fb04440ed1bb2770e6e84a2fadcc515610085e82322e7b1e6e9b79892b3007ea19224f6532c8f503238dfddee9f3fc05b902658afacef7241836ca4960ba675f0c1e365c20957d58e4508c3c87c8d16c9fbc9d3fe2a72575701dac36ce7c311063b9f8f26dac06470fc6d92d021840bd1421d1e6f95db539f0fc989253b77456b81b60503439cc0dd3619f30c329a5c872e2316357ab71b40552d14721d302c06d835736cd963cb128bf36337f24b610f25c409b3842c6f5d26a8031c2
	// encrypted message: 0x1e4cab2781a12f625812dd23969d65b58e594da1efe7b4c5dd7b721ac8edaf909ba907005c027985404ac65481745b4ca8bca50d5b2320ca074a19ae4cbac21717f5e39f0871155f906e0abbe560596bac76c85ff2eb63872bec838803ff0b6b846824d621840d8d23313f6a8f04faaa4ccbf900b936675bd1ea17e461992fbc55a1acee14bb40f0b38869f7b2c10bb084425beaf856f1c394d183a76384ec4676e914bee4befe784abcfd55319bc8cf57cdef3984ca4654b3cf6f063f88ba327822970e8e6221c5e085a71aea0b324ce08da3ac9f5e1095b8bfc33e7408005a1418c7e0e9efcf0f134cd5c6990b1caef9b75e8943c7a95fd2916ce956d96148
	// decrypted message: 0x00a8cf07c340a5d6b3e8e5625e3bf6006f12d70dd5296c0886568f23b56aaf52adca5497f9939f7994b53bf8b9d656a932373881ecd749e8692c8c0cd8c46205a5ed11fb04440ed1bb2770e6e84a2fadcc515610085e82322e7b1e6e9b79892b3007ea19224f6532c8f503238dfddee9f3fc05b902658afacef7241836ca4960ba675f0c1e365c20957d58e4508c3c87c8d16c9fbc9d3fe2a72575701dac36ce7c311063b9f8f26dac06470fc6d92d021840bd1421d1e6f95db539f0fc989253b77456b81b60503439cc0dd3619f30c329a5c872e2316357ab71b40552d14721d302c06d835736cd963cb128bf36337f24b610f25c409b3842c6f5d26a8031c2
	// decoded message: Hello World
}

// ExampleRSASign is example for RSA signing
func ExampleRSASign() {

	var rtn int

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Fatal(err)
	}

	rng := wrap.NewRand(seed)

	// Generating public/private key pair
	RSA_PrivKey, RSA_PubKey := RSAKeyPair_2048(rng, 65537, nil, nil)

	// Message to encrypt
	MESSAGEstr := "Hello World"
	MESSAGE := []byte(MESSAGEstr)
	fmt.Printf("message: %s\n", MESSAGE[:])

	// Signing message
	C, err := PKCS15(wrap.HASH_TYPE_RSA_2048, MESSAGE, wrap.RFS_2048)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("padded message: %x\n", C[:])

	// create signature in S
	S := RSADecrypt_2048(RSA_PrivKey, C[:])
	fmt.Printf("signed message: %x\n", S[:])

	Cgot := RSAEncrypt_2048(RSA_PubKey, S[:])

	fmt.Printf("verify signature message: %x\n", Cgot[:])

	// destroy private key
	RSAPrivateKeyKill_2048(RSA_PrivKey)

	// Use the following only for testing
	rtn = int(wrap.OctetComp(C, Cgot))
	if rtn != 1 {
		log.Fatalf("message doesn't correspond to the expected one: %v", rtn)
	}

	// Output:
	// message: Hello World
	// padded message: 0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d060960864801650304020105000420a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
	// signed message: 13dcd6705321c75c3c7dcb963d3270cb0e81f53abd5afd059d27987894bfbdebb9fc339c2982874f15cd7cd2ecfc8094ddbc8738249c64333b960acc291a82b16aff42d767abe80fdac307e7ff7b40b6dffa204afb2441732ea297068e7f8956677d27dc326d4c77d4a4fcd259e1580368f2b100fb13fcbca269d7db4e53c57d2065041cd31865d8d452cbd650f4f98bb00d71777967b8dc179f5aef71e4d3234fa990781eee977da92850f3977d8ea2d46598eb7160255af3d4ee243f6c24e4344765e788dbeee1fcfc81ec9ba3d47775a5b45059ba48e4bd81689f45b1cffeacd777e3cd61da99e448c6949538443d2e43d1926226dd94397a5880e08b03d6
	// verify signature message: 0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d060960864801650304020105000420a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
}
