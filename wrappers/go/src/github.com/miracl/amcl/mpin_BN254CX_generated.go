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

// #cgo LDFLAGS: -lamcl_curve_BN254CX -lamcl_mpin_BN254CX -lamcl_pairing_BN254CX
// #include <stdio.h>
// #include <stdlib.h>
// #include "amcl.h"
// #include "randapi.h"
// #include "mpin_BN254CX.h"
// #include "utils.h"
// #include "wrappers_generated.h"
import "C"
import "bytes"

const (
	PAS_BN254CX int = int(C.MPIN_PAS)
	PGS_BN254CX int = int(C.MPIN_PGS_BN254CX)
	PFS_BN254CX int = int(C.MPIN_PFS_BN254CX)
	G1S_BN254CX = 2*PFS_BN254CX + 1
	G2S_BN254CX = 4 * PFS_BN254CX
	GTS_BN254CX = 12 * PFS_BN254CX
)

// RandomGenerate_BN254CX returns a random integer where s < q is the order of the group of points on the curve.
func RandomGenerate_BN254CX(rng *Rand) ([]byte, error) {
	r := make([]byte, PGS_BN254CX)
	rtn := C._MPIN_BN254CX_RANDOM_GENERATE(rng.csprng(), *makeOctet(r))
	return r, newError(int(rtn))
}

// GetServerSecret_BN254CX creates a server secret in G2 from a master secret
func GetServerSecret_BN254CX(ms []byte) ([]byte, error) {
	ss := make([]byte, G2S_BN254CX)
	rtn := C._MPIN_BN254CX_GET_SERVER_SECRET(*newOctet(ms), *makeOctet(ss))
	return ss, newError(int(rtn))
}

// RecombineG1_BN254CX adds two members from the group G1
func RecombineG1_BN254CX(r1, r2 []byte) ([]byte, error) {
	r := make([]byte, G1S_BN254CX)
	rtn := C._MPIN_BN254CX_RECOMBINE_G1(*newOctet(r1), *newOctet(r2), *makeOctet(r))
	return r, newError(int(rtn))
}

// RecombineG2_BN254CX adds two members from the group G2
func RecombineG2_BN254CX(w1, w2 []byte) ([]byte, error) {
	w := make([]byte, G2S_BN254CX)
	rtn := C._MPIN_BN254CX_RECOMBINE_G2(*newOctet(w1), *newOctet(w2), *makeOctet(w))
	return w, newError(int(rtn))
}

// GetClientSecret_BN254CX creates a client secret in G1 from a master secret and the hash of the M-Pin Id
func GetClientSecret_BN254CX(masterSecret []byte, hashMPinId []byte) ([]byte, error ) {
	cs := make([]byte, G1S_BN254CX)
	rtn := C._MPIN_BN254CX_GET_CLIENT_SECRET(*newOctet(masterSecret), *newOctet(hashMPinId), *makeOctet(cs))
	return cs, newError(int(rtn))
}

// GetDVSKeyPair_BN254CX randomly generates the public key in G2 for the key-escrow less scheme
// z: input octet pointer to a value for z in rng==nil, nil otherwise
// zOut: output randomly generated private key if rng!=nil, z otherwise
// publicKey: client public key: (z^-1).Q
func GetDVSKeyPair_BN254CX(rng *Rand, z []byte) (zOut, publicKey []byte, err error) {
	publicKey = make([]byte, G2S_BN254CX)

	var rtn C.int
	if rng != nil {
		z = make([]byte, PGS_BN254CX)
		rtn = C._MPIN_BN254CX_GET_DVS_KEYPAIR(rng.csprng(), *makeOctet(z), *makeOctet(publicKey))
	} else {
		rtn = C._MPIN_BN254CX_GET_DVS_KEYPAIR(nil, *newOctet(z), *makeOctet(publicKey))
	}

	return z, publicKey, newError(int(rtn))
}

// GetClientPermit_BN254CX creates a time permit in G1 from a master secret, hash of the M-Pin Id and epoch days
func GetClientPermit_BN254CX(hashType, epochDate int, masterSecret, hashMPinId []byte) ([]byte, error) {
	tp := make([]byte, G1S_BN254CX)
	rtn := C._MPIN_BN254CX_GET_CLIENT_PERMIT(C.int(hashType), C.int(epochDate), *newOctet(masterSecret), *newOctet(hashMPinId), *makeOctet(tp))
	return tp, newError(int(rtn))
}


// ExtractPIN_BN254CX extracts a PIN from the client secret
func ExtractPIN_BN254CX(hashType int, mpinId []byte, PIN int, clientSecret []byte) ([]byte, error) {
	rtn := C._MPIN_BN254CX_EXTRACT_PIN(C.int(hashType), *newOctet(mpinId), C.int(PIN), *newOctet(clientSecret))
	return bytes.TrimRight(clientSecret, "\x00"), newError(int(rtn))
}


// Client_BN254CX performs client side of the one-Pass version of the M-Pin protocol. If Time Permits are
// disabled then set epoch_date = 0.In this case UT is not generated and can be set to nil.
// If Time Permits are enabled, and PIN error detection is OFF, U is not generated and
// can be set to nil. If Time Permits are enabled and PIN error detection is ON then U
// and UT are both generated.
// Args:
//     hashType: Hash function
//     epochDate: Date, in days since the epoch. Set to 0 if Time permits disabled
//     mpinId: M-Pin ID
//     rng: cryptographically secure random number generator
//     x: random number provided as input if rng==nil, otherwise must be nil
//     pin: PIN entered by user
//     token: M-Pin token
//     timePermit: M-Pin time permit
//     message: message to be signed
//     epochTime: Epoch time in seconds
// Returns:
//     errorCode: error from the C function
//     x: Randomly generated integer if R!=nil, otherwise must be provided as an input
//     U: U = x.H(ID)
//     UT: UT = x.(H(ID)+H(epoch_date|H(ID)))
//     V: V = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
//     y: y = H(t|U) or y = H(t|UT) if Time Permits enabled where is t is epoch time
func Client_BN254CX(hashType, epochDate int, mpinId []byte, rng *Rand, x []byte, PIN int, token []byte, timePermit []byte, message []byte, epochTime int) (errorCode int, xOut, y, V, U, UT []byte) {

	var UTOct *C.octet
	var pUT C.octet
	defer OctetFree(&pUT)

	var messageOct *C.octet
	var pmessage C.octet
	defer OctetFree(&pmessage)

	var timePermitOct *C.octet
	var ptimePermit C.octet
	defer OctetFree(&ptimePermit)

	var xOct C.octet
	defer OctetFree(&xOct)

	var prng *C.csprng

	if rng == nil {
		prng = nil
		xStr := string(x)
		xOct = GetOctet(xStr)
	} else {
		prng = rng.csprng()
		xOct = GetOctetZero(PGS_BN254CX)
	}
	if epochDate == 0 {
		UTOct = nil
		timePermitOct = nil
	} else {
		pUT = GetOctetZero(G1S_BN254CX)
		UTOct = &pUT
		TPStr := string(timePermit)
		ptimePermit = GetOctet(TPStr)
		timePermitOct = &ptimePermit
	}
	if message == nil {
		messageOct = nil
	} else {
		messageStr := string(message)
		pmessage = GetOctet(messageStr)
		messageOct = &pmessage
	}

	// Form other Octets
	mpinIdStr := string(mpinId)
	mpinIdOct := GetOctet(mpinIdStr)
	defer OctetFree(&mpinIdOct)
	tokenStr := string(token)
	tokenOct := GetOctet(tokenStr)
	defer OctetFree(&tokenOct)

	VOct := GetOctetZero(G1S_BN254CX)
	defer OctetFree(&VOct)
	UOct := GetOctetZero(G1S_BN254CX)
	defer OctetFree(&UOct)

	yOct := GetOctetZero(PGS_BN254CX)
	defer OctetFree(&yOct)

	rtn := C.MPIN_BN254CX_CLIENT(C.int(hashType), C.int(epochDate), &mpinIdOct, prng, &xOct, C.int(PIN), &tokenOct, &VOct, &UOct, UTOct, timePermitOct, messageOct, C.int(epochTime), &yOct)
	errorCode = int(rtn)

	// Convert octet to bytes
	xOut = OctetToBytes(&xOct)
	V = OctetToBytes(&VOct)
	U = OctetToBytes(&UOct)
	y = OctetToBytes(&yOct)

	if epochDate == 0 {
		return errorCode, xOut[:], y[:], V[:], U[:], nil
	} else {
		UT = OctetToBytes(UTOct)
		return errorCode, xOut[:], y[:], V[:], U[:], UT[:]
	}
}

// Precompute_BN254CX calculate values for use by the client side of M-Pin Full
// Args:
//     token:  M-Pin token
//     hashMPinId: hash of the M-Pin ID
// Returns:
//     errorCcode: error from the C function
//     pc1: Precomputed value one
//     pc2: Precomputed value two
func Precompute_BN254CX(token, hashMPinId []byte) (pc1, pc2 []byte, err error) {
	pc1, pc2 = make([]byte, GTS_BN254CX), make([]byte, GTS_BN254CX)
	rtn := C._MPIN_BN254CX_PRECOMPUTE(*newOctet(token), *newOctet(hashMPinId), nil, *makeOctet(pc1), *makeOctet(pc2))
	return pc1, pc2, newError(int(rtn))
}

// GetG1Multiple_BN254CX calculates W=x*P where random x < q is the order of the group of points on the curve.
// When rng is nil x is Passed in otherwise it is Passed out.
// If type=0 then P is. point on the curve or else P is an octet that has to be
// mapped to the curve
// Args:
//     rng: Pointer to cryptographically secure pseudo-random number generator instance
//     type: determines type of action to be taken
//     x: random number provided as input if rng==nil, otherwise must be nil
//     P: if type=0 a point in G1, else an octet to be mapped to G1
// Returns:
//     x: an output internally randomly generated if rng!=nil, otherwise must be provided as an input
//     W: W = x.P or W = x.M(P), where M(.) is a mapping when type = 0
func GetG1Multiple_BN254CX(rng *Rand, typ int, x []byte, G []byte) (errorCode int, xOut, W []byte) {
	xStr := string(x)
	xOct := GetOctet(xStr)
	defer OctetFree(&xOct)
	GStr := string(G)
	GOct := GetOctet(GStr)
	defer OctetFree(&GOct)

	WOct := GetOctetZero(G1S_BN254CX)
	defer OctetFree(&WOct)

	var prng *C.csprng

	if rng == nil {
		prng = nil
		xStr := string(x)
		xOct = GetOctet(xStr)
	} else {
		prng = rng.csprng()
		xOct = GetOctetZero(PGS_BN254CX)
	}

	rtn := C.MPIN_BN254CX_GET_G1_MULTIPLE(prng, C.int(typ), &xOct, &GOct, &WOct)
	errorCode = int(rtn)

	// Convert octet to bytes
	xOut = OctetToBytes(&xOct)
	W = OctetToBytes(&WOct)

	return errorCode, xOut[:], W[:]
}

// Server_BN254CX performs server side of the one-Pass version of the M-Pin protocol
// with support for the key-escrow less scheme. If Time Permits are disabled,
// set epoch_date = 0, and UT and HTID are not generated and can be set to nil.
// If Time Permits are enabled, and PIN error detection is OFF,
// U and HID are not needed and can be set to nil. If Time Permits are enabled,
// and PIN error detection is ON, U, UT, HID and HTID are all required.
// Args:
//     hashType: Hash function
//     epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
//     epochTime: Epoch time in seconds
//     server_secret: Server secret
//     U: U = x.H(ID)
//     UT: UT = x.(H(ID)+H(epoch_date|H(ID)))
//     V: V = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
//     mpinId: M-Pin ID, or hash of the M-Pin ID in anonymous mode, or M-Pin ID | publicKey in key-escrow less scheme
//     publicKey: client public key in key-escrow less version, or nil otherwise
//     message: message to be signed
//     Kangaroo_BN254CX: Set to true to perform Kangaroo
// Returns:
//     errorCode: error from the C function
//     HID:  H(mpin_id). H is a map to a point on the curve
//     HTID: H(mpin_id)+H(epoch_date|H(mpin_id)). H is a map to a point on the curve
//     E: value to help the Kangaroos to find the PIN error, or nil if not required
//     F: value to help the Kangaroos to find the PIN error, or nil if not required
//     y: y = H(t|U) or y = H(t|UT) if Time Permits enabled used for debug
func Server_BN254CX(hashType, epochDate, epochTime int, serverSecret, U, UT, V, mpinId, publicKey, message []byte, Kangaroo bool) (errorCode int, HID, HTID, y, E, F []byte) {
	serverSecretStr := string(serverSecret)
	serverSecretOct := GetOctet(serverSecretStr)
	defer OctetFree(&serverSecretOct)
	UStr := string(U)
	UOct := GetOctet(UStr)
	defer OctetFree(&UOct)
	VStr := string(V)
	VOct := GetOctet(VStr)
	defer OctetFree(&VOct)
	mpinIdStr := string(mpinId)
	mpinIdOct := GetOctet(mpinIdStr)
	defer OctetFree(&mpinIdOct)

	HIDOct := GetOctetZero(G1S_BN254CX)
	defer OctetFree(&HIDOct)
	HTIDOct := GetOctetZero(G1S_BN254CX)
	defer OctetFree(&HTIDOct)
	yOct := GetOctetZero(PGS_BN254CX)
	defer OctetFree(&yOct)

	var pUT C.octet
	defer OctetFree(&pUT)
	var pmessage C.octet
	defer OctetFree(&pmessage)
	var pE C.octet
	defer OctetFree(&pE)
	var pF C.octet
	defer OctetFree(&pF)
	var pPublicKey C.octet
	defer OctetFree(&pPublicKey)

	var EOct *C.octet
	var FOct *C.octet
	var UTOct *C.octet
	var messageOct *C.octet
	var publicKeyOct *C.octet

	if publicKey == nil {
		publicKeyOct = nil
	} else {
		publicKeyStr := string(publicKey)
		pPublicKey = GetOctet(publicKeyStr)
		publicKeyOct = &pPublicKey
	}
	if UT == nil {
		UTOct = nil
	} else {
		UTStr := string(UT)
		pUT = GetOctet(UTStr)
		UTOct = &pUT
	}
	if message == nil {
		messageOct = nil
	} else {
		messageStr := string(message)
		pmessage = GetOctet(messageStr)
		messageOct = &pmessage
	}
	if !Kangaroo {
		EOct = nil
		FOct = nil
	} else {
		pE = GetOctetZero(GTS_BN254CX)
		EOct = &pE
		pF = GetOctetZero(GTS_BN254CX)
		FOct = &pF
	}

	rtn := C.MPIN_BN254CX_SERVER(C.int(hashType), C.int(epochDate), &HIDOct, &HTIDOct, &yOct, &serverSecretOct, &UOct, UTOct, &VOct, EOct, FOct, &mpinIdOct, messageOct, C.int(epochTime), publicKeyOct)
	errorCode = int(rtn)

	// Convert octet to bytes
	HID = OctetToBytes(&HIDOct)
	HTID = OctetToBytes(&HTIDOct)
	y = OctetToBytes(&yOct)

	if !Kangaroo {
		return errorCode, HID[:], HTID[:], y[:], nil, nil
	} else {
		E = OctetToBytes(EOct)
		F = OctetToBytes(FOct)
		return errorCode, HID[:], HTID[:], y[:], E[:], F[:]
	}
}

// Kangaroo_BN254CX uses Pollards Kangaroos to find PIN error
// Args:
//     E: a member of the group GT
//     F: a member of the group GT =  E^pin_error
// Returns:
//     PINError: error in PIN or 0 if Kangaroos failed
func Kangaroo_BN254CX(E []byte, F []byte) (PINError int) {
	EStr := string(E)
	EOct := GetOctet(EStr)
	defer OctetFree(&EOct)
	FStr := string(F)
	FOct := GetOctet(FStr)
	defer OctetFree(&FOct)

	rtn := C.MPIN_BN254CX_KANGAROO(&EOct, &FOct)
	PINError = int(rtn)

	return PINError
}

// ServerKey_BN254CX calculates AES key on server side for M-Pin Full.Uses UT internally for the
// key calculation or uses U if UT is set to None
// Args:
//     hashType: Hash function
//     Z: Client-side Diffie-Hellman component
//     serverSecret: server secret
//     w: random number generated by the server
//     HM: hash of the protocol transcript
//     HID: H(mpin_id). H is a map to a point on the curve
//     U: U = x.H(ID)
//     UT: UT = x.(H(ID)+H(epoch_date|H(ID)))
// Returns:
//     errorCode: error code from the C function
//     serverAESKey: server AES key
func ServerKey_BN254CX(hashType int, Z, serverSecret, w, HM, HID, U, UT []byte) (errorCode int, serverAESKey []byte) {
	var rtn C.int
	ZStr := string(Z)
	ZOct := GetOctet(ZStr)
	defer OctetFree(&ZOct)
	serverSecretStr := string(serverSecret)
	serverSecretOct := GetOctet(serverSecretStr)
	defer OctetFree(&serverSecretOct)
	wStr := string(w)
	wOct := GetOctet(wStr)
	defer OctetFree(&wOct)
	HMStr := string(HM)
	HMOct := GetOctet(HMStr)
	defer OctetFree(&HMOct)
	HIDStr := string(HID)
	HIDOct := GetOctet(HIDStr)
	defer OctetFree(&HIDOct)
	serverAESKeyOct := GetOctetZero(PAS_BN254CX)
	defer OctetFree(&serverAESKeyOct)
	UStr := string(U)
	UOct := GetOctet(UStr)
	defer OctetFree(&UOct)

	if UT == nil {
		UStr := string(U)
		UOct := GetOctet(UStr)
		defer OctetFree(&UOct)
		rtn = C.MPIN_BN254CX_SERVER_KEY(C.int(hashType), &ZOct, &serverSecretOct, &wOct, &HMOct, &HIDOct, &UOct, nil, &serverAESKeyOct)
	} else {
		UTStr := string(UT)
		UTOct := GetOctet(UTStr)
		defer OctetFree(&UTOct)
		rtn = C.MPIN_BN254CX_SERVER_KEY(C.int(hashType), &ZOct, &serverSecretOct, &wOct, &HMOct, &HIDOct, nil, &UTOct, &serverAESKeyOct)
	}

	errorCode = int(rtn)

	// Convert octet to bytes
	serverAESKey = OctetToBytes(&serverAESKeyOct)

	return errorCode, serverAESKey[:]
}

// ClientKey_BN254CX calculate AES key on client side for M-Pin Full
// Args:
//     hashType: Hash function
//     pc1: precomputed input
//     pc2: precomputed input
//     PIN: PIN number
//     r: locally generated random number
//     x: locally generated random number
//     HM: hash of the protocol transcript
//     T: Server-side Diffie-Hellman component
// Returns:
//     clientAESKey: client AES key
func ClientKey_BN254CX(hashType, PIN int, pc1, pc2, r, x, HM, T []byte) (errorCode int, clientAESKey []byte) {
	pc1Str := string(pc1)
	pc1Oct := GetOctet(pc1Str)
	defer OctetFree(&pc1Oct)
	pc2Str := string(pc2)
	pc2Oct := GetOctet(pc2Str)
	defer OctetFree(&pc2Oct)
	rStr := string(r)
	rOct := GetOctet(rStr)
	defer OctetFree(&rOct)
	xStr := string(x)
	xOct := GetOctet(xStr)
	defer OctetFree(&xOct)
	HMStr := string(HM)
	HMOct := GetOctet(HMStr)
	defer OctetFree(&HMOct)
	TStr := string(T)
	TOct := GetOctet(TStr)
	defer OctetFree(&TOct)

	clientAESKeyOct := GetOctetZero(PAS_BN254CX)
	defer OctetFree(&clientAESKeyOct)

	rtn := C.MPIN_BN254CX_CLIENT_KEY(C.int(hashType), &pc1Oct, &pc2Oct, C.int(PIN), &rOct, &xOct, &HMOct, &TOct, &clientAESKeyOct)
	errorCode = int(rtn)

	// Convert octet to bytes
	clientAESKey = OctetToBytes(&clientAESKeyOct)

	return errorCode, clientAESKey[:]
}

// Server1_BN254CX performs first Pass of the server side of the 3-Pass version of the M-Pin protocol
// If Time Permits are disabled, set epoch_date = 0, and UT and HTID are not generated
// and can be set to nil. If Time Permits are enabled, and PIN error detection is OFF,
// U and HID are not needed and can be set to nil. If Time Permits are enabled,
// and PIN error detection is ON, U, UT, HID and HTID are all required.
// Args:
//     hashType: Hash function
//     epochDate: Date, in days since the epoch. Set to 0 if Time permits disabled
//     mpinId: M-Pin ID or hash of the M-Pin ID in anonymous mode
// Returns:
//     HID:  H(mpin_id). H is a map to a point on the curve
//     HTID: H(mpin_id)+H(epoch_date|H(mpin_id)). H is a map to a point on the curve
func Server1_BN254CX(hashType, epochDate int, mpinId []byte) (HID, HTID []byte) {
	// Form Octets
	mpinIdStr := string(mpinId)
	mpinIdOct := GetOctet(mpinIdStr)
	defer OctetFree(&mpinIdOct)

	HIDOct := GetOctetZero(G1S_BN254CX)
	defer OctetFree(&HIDOct)
	HTIDOct := GetOctetZero(G1S_BN254CX)
	defer OctetFree(&HTIDOct)

	C.MPIN_BN254CX_SERVER_1(C.int(hashType), C.int(epochDate), &mpinIdOct, &HIDOct, &HTIDOct)

	// Convert octet to bytes
	HID = OctetToBytes(&HIDOct)
	HTID = OctetToBytes(&HTIDOct)

	return HID[:], HTID[:]
}

// Server2_BN254CX performs server side of the three-Pass version of the M-Pin protocol, wiht
// support for the key-escrow less scheme.  If Time Permits are disabled,
// set epoch_date = 0, and UT and HTID are not generated and can be set to nil.
// If Time Permits are enabled, and PIN error detection is OFF,
// U and HID are not needed and can be set to nil. If Time Permits are enabled,
// and PIN error detection is ON, U, UT, HID and HTID are all required.
// Args:
//     epochDate: Date in days since the epoch. Set to 0 if Time permits disabled
//     HID:  H(mpin_id). H is a map to a point on the curve
//     HTID: H(mpin_id)+H(epoch_date|H(mpin_id)). H is a map to a point on the curve
//     y: locally generated random number
//     publicKey: client public key in key-escrow less scheme, nil otherwise
//     server_secret: Server secret
//     U: U = x.H(ID)
//     UT: UT = x.(H(ID)+H(epoch_date|H(ID)))
//     V: V = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
//     Kangaroo_BN254CX: Set to true to perform Kangaroo_BN254CX
// Returns:
//     errorCode: error from the C function
//     E: value to help the Kangaroo_BN254CXs to find the PIN error, or nil Kangaroo_BN254CX is set to false
//     F: value to help the Kangaroo_BN254CXs to find the PIN error, or nil Kangaroo_BN254CX is set to false
func Server2_BN254CX(epochDate int, HID []byte, HTID []byte, publicKey []byte, y []byte, serverSecret []byte, U []byte, UT []byte, V []byte, Kangaroo_BN254CX bool) (errorCode int, E []byte, F []byte) {
	// Form Octets
	HIDStr := string(HID)
	HIDOct := GetOctet(HIDStr)
	defer OctetFree(&HIDOct)
	HTIDStr := string(HTID)
	HTIDOct := GetOctet(HTIDStr)
	defer OctetFree(&HTIDOct)
	yStr := string(y)
	yOct := GetOctet(yStr)
	defer OctetFree(&yOct)
	serverSecretStr := string(serverSecret)
	serverSecretOct := GetOctet(serverSecretStr)
	defer OctetFree(&serverSecretOct)
	UStr := string(U)
	UOct := GetOctet(UStr)
	defer OctetFree(&UOct)
	VStr := string(V)
	VOct := GetOctet(VStr)
	defer OctetFree(&VOct)

	var EOct *C.octet
	var FOct *C.octet
	var UTOct *C.octet
	var publicKeyOct *C.octet

	var pUT C.octet
	defer OctetFree(&pUT)
	var pE C.octet
	defer OctetFree(&pE)
	var pF C.octet
	defer OctetFree(&pF)
	var pPublicKey C.octet
	defer OctetFree(&pPublicKey)

	if publicKey == nil {
		publicKeyOct = nil
	} else {
		publicKeyStr := string(publicKey)
		pPublicKey = GetOctet(publicKeyStr)
		publicKeyOct = &pPublicKey
	}
	if UT == nil {
		UTOct = nil
	} else {
		UTStr := string(UT)
		pUT = GetOctet(UTStr)
		UTOct = &pUT
	}
	if !Kangaroo_BN254CX {
		EOct = nil
		FOct = nil
	} else {
		pE = GetOctetZero(GTS_BN254CX)
		EOct = &pE
		pF = GetOctetZero(GTS_BN254CX)
		FOct = &pF
	}

	rtn := C.MPIN_BN254CX_SERVER_2(C.int(epochDate), &HIDOct, &HTIDOct, &yOct, &serverSecretOct, &UOct, UTOct, &VOct, EOct, FOct, publicKeyOct)

	errorCode = int(rtn)

	if !Kangaroo_BN254CX {
		return errorCode, nil, nil
	} else {
		E = OctetToBytes(EOct)
		F = OctetToBytes(FOct)
		return errorCode, E, F
	}
}

// Client1_BN254CX performs first Pass of the client side of the three Pass version of the M-Pin protocol.
// If Time Permits are disabled then set epoch_date = 0.In this case UT is not generated0
// and can be set to nil. If Time Permits are enabled, and PIN error detection is OFF,
// U is not generated and can be set to nil. If Time Permits are enabled and PIN error
// detection is ON then U and UT are both generated.
// Args:
//     hashType: Hash function
//     epochDate: Date, in days since the epoch. Set to 0 if Time permits disabled
//     mpinId: M-Pin ID
//     rng: cryptographically secure random number generator
//     x: random number provided as input if rng==nil, otherwise must be nil
//     PIN: PIN entered by user
//     token: M-Pin token
//     timePermit: M-Pin time permit
// Returns:
//     errorCode: error from the C function
//     x: Randomly generated integer if rng!=nil, otherwise must be provided as an input
//     U: U = x.H(ID)
//     UT: UT = x.(H(ID)+H(epoch_date|H(ID)))
//     SEC: SEC = CS+TP, where CS is the reconstructed client secret and TP is the time permit
func Client1_BN254CX(hashType, epochDate int, mpinId []byte, rng *Rand, x []byte, PIN int, token []byte, timePermit []byte) (errorCode int, xOut, SEC, U, UT []byte) {
	// Form Octets
	mpinIdStr := string(mpinId)
	mpinIdOct := GetOctet(mpinIdStr)
	defer OctetFree(&mpinIdOct)

	tokenStr := string(token)
	tokenOct := GetOctet(tokenStr)
	defer OctetFree(&tokenOct)

	SECOct := GetOctetZero(G1S_BN254CX)
	defer OctetFree(&SECOct)
	UOct := GetOctetZero(G1S_BN254CX)
	defer OctetFree(&UOct)

	var pUT C.octet
	defer OctetFree(&pUT)
	var pTP C.octet
	defer OctetFree(&pTP)
	var timePermitOct *C.octet
	var UTOct *C.octet

	var xOct C.octet
	defer OctetFree(&xOct)

	var prng *C.csprng

	if rng == nil {
		prng = nil
		xStr := string(x)
		xOct = GetOctet(xStr)
	} else {
		prng = rng.csprng()
		xOct = GetOctetZero(PGS_BN254CX)
	}
	if epochDate == 0 {
		timePermitOct = nil
		UTOct = nil
	} else {
		pUT = GetOctetZero(G1S_BN254CX)
		UTOct = &pUT
		TPStr := string(timePermit)
		pTP = GetOctet(TPStr)
		timePermitOct = &pTP

	}

	rtn := C.MPIN_BN254CX_CLIENT_1(C.int(hashType), C.int(epochDate), &mpinIdOct, prng, &xOct, C.int(PIN), &tokenOct, &SECOct, &UOct, UTOct, timePermitOct)

	errorCode = int(rtn)
	// Convert octet to bytes
	xOut = OctetToBytes(&xOct)
	SEC = OctetToBytes(&SECOct)
	U = OctetToBytes(&UOct)
	if epochDate == 0 {
		return errorCode, xOut[:], SEC[:], U[:], nil
	} else {
		UT = OctetToBytes(UTOct)
		return errorCode, xOut[:], SEC[:], U[:], UT[:]
	}
}

// Client2_BN254CX performs second Pass of the client side of the 3-Pass version of the M-Pin protocol
// Args:
//     x: locally generated random number
//     y: random challenge from server
//     SEC: CS+TP, where CS is the reconstructed client secret and TP is the time permit
// Returns:
//     V: V = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
func Client2_BN254CX(x, y, SEC []byte) ([]byte, error) {
	rtn := C._MPIN_BN254CX_CLIENT_2(*newOctet(x), *newOctet(y), *newOctet(SEC))
	return bytes.TrimRight(SEC, "\x00"), newError(int(rtn))
}
