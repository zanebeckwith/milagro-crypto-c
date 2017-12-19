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

// Generated by gen/wrappers/main.go from wrappers.go.tmpl.

package amcl

import "github.com/miracl/amcl/wrap"

// ECPKeyPairGenerate_BN254 is a wrapper of wrap.ECP_BN254_KEY_PAIR_GENERATE
func ECPKeyPairGenerate_BN254(R *wrap.Rand, s []byte) (sResult []byte, W []byte, err error) {

	var sOct *wrap.Octet
	if s != nil {
		sOct = wrap.NewOctet(s)
		defer sOct.Free()
	} else {
		sSize := wrap.EGS_BN254
		sOct = wrap.MakeOctet(sSize)
		defer sOct.Free()
	}

	WSize := 2*wrap.EFS_BN254 + 1
	WOct := wrap.MakeOctet(WSize)
	defer WOct.Free()

	err = wrap.ECP_BN254_KEY_PAIR_GENERATE(R, sOct, WOct)

	sResult = sOct.ToBytes()

	W = WOct.ToBytes()
	return
}

// ECPPublicKeyValidate_BN254 is a wrapper of wrap.ECP_BN254_PUBLIC_KEY_VALIDATE
func ECPPublicKeyValidate_BN254(W []byte) (err error) {

	WOct := wrap.NewOctet(W)
	defer WOct.Free()

	err = wrap.ECP_BN254_PUBLIC_KEY_VALIDATE(WOct)

	return
}

// ECPSpDsa_BN254 is a wrapper of wrap.ECP_BN254_SP_DSA
func ECPSpDsa_BN254(h int, R *wrap.Rand, k []byte, s []byte, M []byte) (c []byte, d []byte, err error) {

	kOct := wrap.NewOctet(k)
	defer kOct.Free()

	sOct := wrap.NewOctet(s)
	defer sOct.Free()

	MOct := wrap.NewOctet(M)
	defer MOct.Free()

	cSize := wrap.EGS_BN254
	cOct := wrap.MakeOctet(cSize)
	defer cOct.Free()

	dSize := wrap.EGS_BN254
	dOct := wrap.MakeOctet(dSize)
	defer dOct.Free()

	err = wrap.ECP_BN254_SP_DSA(h, R, kOct, sOct, MOct, cOct, dOct)

	c = cOct.ToBytes()

	d = dOct.ToBytes()
	return
}

// ECPVpDsa_BN254 is a wrapper of wrap.ECP_BN254_VP_DSA
func ECPVpDsa_BN254(h int, W []byte, M []byte, c []byte, d []byte) (err error) {

	WOct := wrap.NewOctet(W)
	defer WOct.Free()

	MOct := wrap.NewOctet(M)
	defer MOct.Free()

	cOct := wrap.NewOctet(c)
	defer cOct.Free()

	dOct := wrap.NewOctet(d)
	defer dOct.Free()

	err = wrap.ECP_BN254_VP_DSA(h, WOct, MOct, cOct, dOct)

	return
}
