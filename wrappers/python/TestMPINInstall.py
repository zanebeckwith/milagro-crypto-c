#!/usr/bin/env python

"""
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
"""
import os
import unittest
import json
import hashlib
import mpin

HASH_TYPE_MPIN = mpin.SHA256


class TestMPIN(unittest.TestCase):
    """Tests M-Pin crypto code"""

    def setUp(self):

        # Form MPin ID
        endUserData = {
            "issued": "2013-10-19T06:12:28Z",
            "userID": "testUser@miracl.com",
            "mobile": 1,
            "salt": "e985da112a378c222cfc2f7226097b0c"
        }
        self.mpin_id = json.dumps(endUserData)

        # Hash value of MPIN_ID
        self.hash_mpin_id = mpin.hash_id(HASH_TYPE_MPIN, self.mpin_id)

        # Assign a seed value
        seedHex = "3ade3d4a5c698e8910bf92f25d97ceeb7c25ed838901a5cb5db2cf25434c1fe76c7f79b7af2e5e1e4988e4294dbd9bd9fa3960197fb7aec373609fb890d74b16a4b14b2ae7e23b75f15d36c21791272372863c4f8af39980283ae69a79cf4e48e908f9e0"
        self.seed = seedHex.decode("hex")

        self.date = 16238

    def test_1(self):
        """test_1 Good PIN and good token"""
        PIN1 = 1234
        PIN2 = 1234

        # random number generator
        rng = mpin.create_csprng(self.seed)

        # Generate Client master secret share for MIRACL and Customer
        rtn, ms1 = mpin.random_generate(rng)
        self.assertEqual(rtn, 0)
        rtn, ms2 = mpin.random_generate(rng)
        self.assertEqual(rtn, 0)

        # Generate server secret shares
        rtn, ss1 = mpin.get_server_secret(ms1)
        self.assertEqual(rtn, 0)
        rtn, ss2 = mpin.get_server_secret(ms2)
        self.assertEqual(rtn, 0)

        # Combine server secret shares
        rtn, server_secret = mpin.recombine_G2(ss1, ss2)
        self.assertEqual(rtn, 0)

        # Generate client secret shares
        rtn, cs1 = mpin.get_client_secret(ms1, self.hash_mpin_id)
        self.assertEqual(rtn, 0)
        rtn, cs2 = mpin.get_client_secret(ms2, self.hash_mpin_id)
        self.assertEqual(rtn, 0)

        # Combine client secret shares
        rtn, client_secret = mpin.recombine_G1(cs1, cs2)
        self.assertEqual(rtn, 0)

        # Generate Time Permit shares
        rtn, tp1 = mpin.get_client_permit(
            HASH_TYPE_MPIN, self.date, ms1, self.hash_mpin_id)
        self.assertEqual(rtn, 0)
        rtn, tp2 = mpin.get_client_permit(
            HASH_TYPE_MPIN, self.date, ms2, self.hash_mpin_id)
        self.assertEqual(rtn, 0)

        # Combine Time Permit shares
        rtn, time_permit = mpin.recombine_G1(tp1, tp2)
        self.assertEqual(rtn, 0)

        # Client extracts PIN from secret to create Token
        rtn, token = mpin.extract_pin(
            HASH_TYPE_MPIN, self.mpin_id, PIN1, client_secret)
        self.assertEqual(rtn, 0)

        # Client first pass
        rtn, x, u, ut, sec = mpin.client_1(HASH_TYPE_MPIN,
                                           self.date, self.mpin_id, rng, None, PIN2, token, time_permit)
        self.assertEqual(rtn, 0)

        # Server calculates H(ID) and H(T|H(ID))
        HID, HTID = mpin.server_1(HASH_TYPE_MPIN, self.date, self.mpin_id)

        # Server generates Random number Y and sends it to Client
        rtn, y = mpin.random_generate(rng)
        self.assertEqual(rtn, 0)

        # Client second pass
        rtn, v = mpin.client_2(x, y, sec)
        self.assertEqual(rtn, 0)

        # Server second pass
        rtn, E, F = mpin.server_2(
            self.date, HID, HTID, y, server_secret, u, ut, v)
        self.assertEqual(rtn, 0)

    def test_2(self):
        """test_2 Bad PIN and good token"""
        PIN1 = 1234
        PIN2 = 2000

        # random number generator
        rng = mpin.create_csprng(self.seed)

        # Generate Client master secret share for MIRACL and Customer
        rtn, ms1 = mpin.random_generate(rng)
        self.assertEqual(rtn, 0)
        rtn, ms2 = mpin.random_generate(rng)
        self.assertEqual(rtn, 0)

        # Generate server secret shares
        rtn, ss1 = mpin.get_server_secret(ms1)
        self.assertEqual(rtn, 0)
        rtn, ss2 = mpin.get_server_secret(ms2)
        self.assertEqual(rtn, 0)

        # Combine server secret shares
        rtn, server_secret = mpin.recombine_G2(ss1, ss2)
        self.assertEqual(rtn, 0)

        # Generate client secret shares
        rtn, cs1 = mpin.get_client_secret(ms1, self.hash_mpin_id)
        self.assertEqual(rtn, 0)
        rtn, cs2 = mpin.get_client_secret(ms2, self.hash_mpin_id)
        self.assertEqual(rtn, 0)

        # Combine client secret shares
        rtn, client_secret = mpin.recombine_G1(cs1, cs2)
        self.assertEqual(rtn, 0)

        # Generate Time Permit shares
        rtn, tp1 = mpin.get_client_permit(
            HASH_TYPE_MPIN, self.date, ms1, self.hash_mpin_id)
        self.assertEqual(rtn, 0)
        rtn, tp2 = mpin.get_client_permit(
            HASH_TYPE_MPIN, self.date, ms2, self.hash_mpin_id)
        self.assertEqual(rtn, 0)

        # Combine Time Permit shares
        rtn, time_permit = mpin.recombine_G1(tp1, tp2)
        self.assertEqual(rtn, 0)

        # Client extracts PIN from secret to create Token
        rtn, token = mpin.extract_pin(
            HASH_TYPE_MPIN, self.mpin_id, PIN1, client_secret)
        self.assertEqual(rtn, 0)

        # Client first pass
        rtn, x, u, ut, sec = mpin.client_1(HASH_TYPE_MPIN,
                                           self.date, self.mpin_id, rng, None, PIN2, token, time_permit)
        self.assertEqual(rtn, 0)

        # Server calculates H(ID) and H(T|H(ID))
        HID, HTID = mpin.server_1(HASH_TYPE_MPIN, self.date, self.mpin_id)

        # Server generates Random number Y and sends it to Client
        rtn, y = mpin.random_generate(rng)
        self.assertEqual(rtn, 0)

        # Client second pass
        rtn, v = mpin.client_2(x, y, sec)
        self.assertEqual(rtn, 0)

        # Server second pass
        rtn, E, F = mpin.server_2(
            self.date, HID, HTID, y, server_secret, u, ut, v)
        self.assertEqual(rtn, -19)

    def test_3(self):
        """test_2 Good PIN and bad token"""
        PIN1 = 1234
        PIN2 = 1234

        # random number generator
        rng = mpin.create_csprng(self.seed)

        # Generate Client master secret share for MIRACL and Customer
        rtn, ms1 = mpin.random_generate(rng)
        self.assertEqual(rtn, 0)
        rtn, ms2 = mpin.random_generate(rng)
        self.assertEqual(rtn, 0)

        # Generate server secret shares
        rtn, ss1 = mpin.get_server_secret(ms1)
        self.assertEqual(rtn, 0)
        rtn, ss2 = mpin.get_server_secret(ms2)
        self.assertEqual(rtn, 0)

        # Combine server secret shares
        rtn, server_secret = mpin.recombine_G2(ss1, ss2)
        self.assertEqual(rtn, 0)

        # Generate client secret shares
        rtn, cs1 = mpin.get_client_secret(ms1, self.hash_mpin_id)
        self.assertEqual(rtn, 0)
        rtn, cs2 = mpin.get_client_secret(ms2, self.hash_mpin_id)
        self.assertEqual(rtn, 0)

        # Combine client secret shares
        rtn, client_secret = mpin.recombine_G1(cs1, cs2)
        self.assertEqual(rtn, 0)

        # Generate Time Permit shares
        rtn, tp1 = mpin.get_client_permit(
            HASH_TYPE_MPIN, self.date, ms1, self.hash_mpin_id)
        self.assertEqual(rtn, 0)
        rtn, tp2 = mpin.get_client_permit(
            HASH_TYPE_MPIN, self.date, ms2, self.hash_mpin_id)
        self.assertEqual(rtn, 0)

        # Combine Time Permit shares
        rtn, time_permit = mpin.recombine_G1(tp1, tp2)
        self.assertEqual(rtn, 0)

        # Client extracts PIN from secret to create Token
        rtn, token = mpin.extract_pin(
            HASH_TYPE_MPIN, self.mpin_id, PIN1, client_secret)
        self.assertEqual(rtn, 0)

        # Client first pass
        rtn, x, u, ut, sec = mpin.client_1(HASH_TYPE_MPIN,
                                           self.date, self.mpin_id, rng, None, PIN2, token, time_permit)
        self.assertEqual(rtn, 0)

        # Server calculates H(ID) and H(T|H(ID))
        HID, HTID = mpin.server_1(HASH_TYPE_MPIN, self.date, self.mpin_id)

        # Server generates Random number Y and sends it to Client
        rtn, y = mpin.random_generate(rng)
        self.assertEqual(rtn, 0)

        # Client second pass
        rtn, v = mpin.client_2(x, y, sec)
        self.assertEqual(rtn, 0)

        # Server second pass
        # v is equal to ut to model a bad token
        rtn, E, F = mpin.server_2(
            self.date, HID, HTID, y, server_secret, u, ut, ut)
        self.assertEqual(rtn, -19)

    def test_4(self):
        """test_4 Test hash function"""
        for i in range(1, 10000):
            bytesStr = os.urandom(128)
            hash_object2 = hashlib.sha256(bytesStr)
            digest = hash_object2.hexdigest()
            hash_mpin_id = mpin.hash_id(HASH_TYPE_MPIN, bytesStr)
            self.assertEqual(digest, hash_mpin_id.encode("hex"))

    def test_5(self):
        """test_5 Make sure all client secret are unique"""
        # random number generator
        rng = mpin.create_csprng(self.seed)

        # Generate master secret share
        rtn, ms1 = mpin.random_generate(rng)
        self.assertEqual(rtn, 0)

        s = set()
        match = 0
        for i in range(1, 1000):
            rand_val = os.urandom(32)
            hash_mpin_id = mpin.hash_id(HASH_TYPE_MPIN, rand_val)

            # Generate client secret shares
            rtn, cs1 = mpin.get_client_secret(ms1, hash_mpin_id)
            self.assertEqual(rtn, 0)
            cs1Hex = cs1.encode("hex")
            if cs1Hex in s:
                match = 1
            self.assertEqual(match, 0)
            s.add(cs1Hex)

    def test_6(self):
        """test_6 Make sure all one time passwords are random i.e. they should collide"""
        # random number generator
        rng = mpin.create_csprng(self.seed)

        s = set()
        match = 0
        for i in range(1, 10000):
            OTP = mpin.generate_otp(rng)
            if OTP in s:
                # print i
                match = 1
            s.add(OTP)
        self.assertEqual(match, 1)

    def test_7(self):
        """test_7 Make sure all random values are random i.e. they should collide"""
        # random number generator
        rng = mpin.create_csprng(self.seed)

        # Generate 4 byte random number
        s = set()
        match = 0
        for i in range(1, 208900):
            random = mpin.generate_random(rng, 4)
            # print i, "  ", random.encode("hex")
            if random in s:
                match = 1
                break
            s.add(random)
        self.assertEqual(match, 1)

    def test_8(self):
        """test_8 AES-GCM: Successful encryption and decryption"""

        # Generate 16 byte key
        key = os.urandom(mpin.PAS)

        # Generate 12 byte IV
        iv = os.urandom(mpin.IVL)

        # Generate a 32 byte random header
        header = os.urandom(32)

        # Plaintext input
        plaintext1 = "A test message"

        ciphertext, tag1 = mpin.aes_gcm_encrypt(key, iv, header, plaintext1)

        plaintext2, tag2 = mpin.aes_gcm_decrypt(key, iv, header, ciphertext)

        self.assertEqual(tag1, tag2)
        self.assertEqual(plaintext1, plaintext2)

    def test_9(self):
        """test_9 AES-GCM: Failed encryption and decryption by changing a ciphertext byte"""

        # Generate 16 byte key
        key = os.urandom(mpin.PAS)

        # Generate 12 byte IV
        iv = os.urandom(mpin.IVL)

        # Generate a 32 byte random header
        header = os.urandom(32)

        # Plaintext input
        plaintext1 = "A test message"

        ciphertext, tag1 = mpin.aes_gcm_encrypt(key, iv, header, plaintext1)

        new = list(ciphertext)
        new[0] = "a"
        ciphertext_bad = ''.join(new)

        plaintext2, tag2 = mpin.aes_gcm_decrypt(
            key, iv, header, ciphertext_bad)

        self.assertNotEqual(tag1, tag2)
        self.assertNotEqual(plaintext1, plaintext2)

    def test_9_1(self):
        """test_10 AES-GCM: Failed encryption and decryption by changing a header byte"""

        # Generate 16 byte key
        key = os.urandom(mpin.PAS)

        # Generate 12 byte IV
        iv = os.urandom(mpin.IVL)

        # Generate a 32 byte random header
        header = os.urandom(32)

        # Plaintext input
        plaintext1 = "A test message"

        ciphertext, tag1 = mpin.aes_gcm_encrypt(key, iv, header, plaintext1)

        new = list(header)
        new[0] = "a"
        header_bad = ''.join(new)

        plaintext2, tag2 = mpin.aes_gcm_decrypt(
            key, iv, header_bad, ciphertext)

        self.assertNotEqual(tag1, tag2)
        self.assertEqual(plaintext1, plaintext2)

if __name__ == '__main__':
    # Run tests
    unittest.main()
