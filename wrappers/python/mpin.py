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


"""
mpin

This module use cffi to access the c functions in the mpin library.

There is also an example usage program in this file.

"""
import cffi
import platform

# MPIN Group Size
PGS = 32
# MPIN Field Size
PFS = 32
G1 = 2*PFS + 1
G2 = 4*PFS
# Hash Size
HASH_BYTES = 32
# AES-GCM IV length
IVL = 12
# MPIN Symmetric Key Size
PAS = 16

ffi = cffi.FFI()
ffi.cdef("""
typedef struct {
unsigned int ira[21];  /* random number...   */
int rndptr;   /* ...array & pointer */
unsigned int borrow;
int pool_ptr;
char pool[32];    /* random pool */
} csprng;

typedef struct
{
    int len;
    int max;
    char *val;
} octet;

extern unsigned int MPIN_GET_TIME(void);
extern void MPIN_Y(int,octet *,octet *);
extern void MPIN_HASH_ID(octet *,octet *);
extern int MPIN_EXTRACT_PIN(octet *,int,octet *);
extern int MPIN_CLIENT(int d,octet *ID,csprng *R,octet *x,int pin,octet *T,octet *V,octet *U,octet *UT,octet *TP, octet* MESSAGE, int t, octet *y);
extern int MPIN_CLIENT_1(int,octet *,csprng *,octet *,int,octet *,octet *,octet *,octet *,octet *);
extern int MPIN_RANDOM_GENERATE(csprng *,octet *);
extern int MPIN_CLIENT_2(octet *,octet *,octet *);
extern void MPIN_SERVER_1(int,octet *,octet *,octet *);
extern int MPIN_SERVER_2(int,octet *,octet *,octet *,octet *,octet *,octet *,octet *,octet *,octet *);
extern int MPIN_SERVER(int d,octet *HID,octet *HTID,octet *y,octet *SS,octet *U,octet *UT,octet *V,octet *E,octet *F,octet *ID,octet *MESSAGE, int t);
extern int MPIN_RECOMBINE_G1(octet *,octet *,octet *);
extern int MPIN_RECOMBINE_G2(octet *,octet *,octet *);
extern int MPIN_KANGAROO(octet *,octet *);

extern int MPIN_ENCODING(csprng *,octet *);
extern int MPIN_DECODING(octet *);

extern unsigned int MPIN_today(void);
extern void MPIN_CREATE_CSPRNG(csprng *,octet *);
extern void MPIN_KILL_CSPRNG(csprng *);
extern int MPIN_PRECOMPUTE(octet *,octet *,octet *,octet *);
extern int MPIN_SERVER_KEY(octet *Z,octet *SS,octet *w,octet *p,octet *I,octet *U,octet *UT,octet *K);
extern int MPIN_CLIENT_KEY(octet *g1,octet *g2,int pin,octet *r,octet *x,octet *p,octet *T,octet *K);
extern int MPIN_GET_G1_MULTIPLE(csprng *,int,octet *,octet *,octet *);
extern int MPIN_GET_CLIENT_SECRET(octet *,octet *,octet *);
extern int MPIN_GET_CLIENT_PERMIT(int,octet *,octet *,octet *);
extern int MPIN_GET_SERVER_SECRET(octet *,octet *);
extern int MPIN_TEST_PAIRING(octet *,octet *);
extern void hex2bytes(char *hex, char *bin);
extern void generateRandom(csprng*, octet*);
extern int generateOTP(csprng*);
extern void MPIN_AES_GCM_ENCRYPT(octet *K,octet *IV,octet *H,octet *P,octet *C,octet *T);
extern void MPIN_AES_GCM_DECRYPT(octet *K,octet *IV,octet *H,octet *C,octet *P,octet *T);
extern void MPIN_HASH_ALL(octet *I,octet *U,octet *CU,octet *V,octet *Y,octet *R,octet *W,octet *H);

""")

if (platform.system() == 'Windows'):
    libmpin = ffi.dlopen("libmpin.dll")
elif (platform.system() == 'Darwin'):
    libmpin = ffi.dlopen("libmpin.dylib")
else:
    libmpin = ffi.dlopen("libmpin.so")


def to_hex(octetValue):
    """Converts an octet type into a string

    Add all the values in an octet into an array. This arrays is then
    converted to a string and hex encoded.

    Args::

        octetValue. An octet type

    Returns::

        String

    Raises:
        Exception
    """
    i = 0
    val = []
    while i < octetValue[0].len:
        val.append(octetValue[0].val[i])
        i = i+1
    return ''.join(val).encode("hex")

def make_octet(length, value=None):
    """Generates an octet

    Generates an empty octet or one filled with the input value
    
    Args::
        
        length: Length of empty octet
        value:  Data to assign to octet      
           
    Returns::
        
        oct_ptr: octet pointer
        val: data associated with octet

    Raises:
        
    """        
    oct_ptr = ffi.new("octet*")    
    if value:
        val = ffi.new("char [%s]" % len(value), value)
        oct_ptr.val = val
        oct_ptr.max = len(value)
        oct_ptr.len = len(value)
    else:
        val = ffi.new("char []", length)
        oct_ptr.val = val
        oct_ptr.max = length
        oct_ptr.len = length        
    return oct_ptr, val


if __name__ == "__main__":
    # Print hex values
    DEBUG = False
    # Require user input
    INPUT = False
    SINGLE_PASS = False
    TIME_PERMITS = True
    MPIN_FULL = False
    PIN_ERROR = True
    USE_ANONYMOUS = False

    if TIME_PERMITS:
        date = libmpin.MPIN_today()
    else:
        date = 0

    # Seed
    seedHex = "3ade3d4a5c698e8910bf92f25d97ceeb7c25ed838901a5cb5db2cf25434c1fe76c7f79b7af2e5e1e4988e4294dbd9bd9fa3960197fb7aec373609fb890d74b16a4b14b2ae7e23b75f15d36c21791272372863c4f8af39980283ae69a79cf4e48e908f9e0"
    seed = seedHex.decode("hex")

    # Identity
    if INPUT:
        identity = raw_input("Please enter identity:")
    else:
        identity = "user@miracl.com"
    MPIN_ID, MPIN_ID_val = make_octet(None,identity)

    # Master Secret Shares
    MS1, MS1_val = make_octet(PGS)
    MS2, MS2_val = make_octet(PGS)

    # Hash value of MPIN_ID
    HASH_MPIN_ID, HASH_MPIN_ID_val = make_octet(HASH_BYTES)

    # Client secret and shares 
    CS1, CS1_val = make_octet(G1)
    CS2, CS2_val = make_octet(G1)
    SEC, SEC_val = make_octet(G1)

    # Server secret and shares
    SS1, SS1_val = make_octet(G2)
    SS2, SS2_val = make_octet(G2)
    SERVER_SECRET, SERVER_SECRET_val  = make_octet(G2)

    # Time Permit and shares
    TP1, TP1_val = make_octet(G1)
    TP2, TP2_val = make_octet(G1)
    TIME_PERMIT, TIME_PERMIT_val = make_octet(G1)

    # Token stored on computer 
    TOKEN, TOKEN_val = make_octet(G1)

    # H(ID)
    HID, HID_val = make_octet(G1)

    # H(T|H(ID))
    HTID, HTID_val = make_octet(G1)

    UT, UT_val = make_octet(G1)

    U, U_val = make_octet(G1)

    X, X_val = make_octet(PGS)
    Y, Y_val = make_octet(PGS)

    lenGT = 12*PFS
    E, E_val = make_octet(lenGT)
    F, F_val = make_octet(lenGT)

    # MPIN Full
    R, R_val = make_octet(PGS)
    W, W_val = make_octet(PGS)
    Z, Z_val = make_octet(G1)
    T, T_val = make_octet(G1)

    TATE1, TATE1_val = make_octet(lenGT)
    TATE2, TATE2_val = make_octet(lenGT)

    SK, SK_val = make_octet(PAS)
    CK, CK_val = make_octet(PAS)

    # Hash value of transmission
    HM, HM_val = make_octet(HASH_BYTES)

    if date:
        prHID = HTID
        if not PIN_ERROR:
            U = ffi.NULL
    else:
        HTID = ffi.NULL
        UT = ffi.NULL
        prHID = HID
        TIME_PERMIT = ffi.NULL

    if not PIN_ERROR:
        E = ffi.NULL
        F = ffi.NULL

    # Assign a seed value
    RAW, RAW_val = make_octet(None,seed)
    if DEBUG:
        print "RAW: %s" % to_hex(RAW)

    # random number generator
    RNG = ffi.new("csprng*")
    libmpin.MPIN_CREATE_CSPRNG(RNG, RAW)

    # Hash MPIN_ID
    libmpin.MPIN_HASH_ID(MPIN_ID, HASH_MPIN_ID)
    if DEBUG:
        print "MPIN_ID: %s" % to_hex(MPIN_ID)
        print "HASH_MPIN_ID: %s" % toHex(HASH_MPIN_ID)

    if USE_ANONYMOUS:
        pID = HASH_MPIN_ID
    else:
        pID = MPIN_ID
        
    # Generate master secret for MIRACL and Customer
    rtn = libmpin.MPIN_RANDOM_GENERATE(RNG, MS1)
    if rtn != 0:
        print "libmpin.MPIN_RANDOM_GENERATE(RNG,MS1) Error %s", rtn
    rtn = libmpin.MPIN_RANDOM_GENERATE(RNG, MS2)
    if rtn != 0:
        print "libmpin.MPIN_RANDOM_GENERATE(RNG,MS2) Error %s" % rtn
    if DEBUG:
        print "MS1: %s" % toHex(MS1)
        print "MS2: %s" % toHex(MS2)

    # Generate server secret shares
    rtn = libmpin.MPIN_GET_SERVER_SECRET(MS1, SS1)
    if rtn != 0:
        print "libmpin.MPIN_GET_SERVER_SECRET(MS1,SS1) Error %s" % rtn
    rtn = libmpin.MPIN_GET_SERVER_SECRET(MS2, SS2)
    if rtn != 0:
        print "libmpin.MPIN_GET_SERVER_SECRET(MS2,SS2) Error %s" % rtn
    if DEBUG:
        print "SS1: %s" % toHex(SS1)
        print "SS2: %s" % toHex(SS2)

    # Combine server secret shares
    rtn = libmpin.MPIN_RECOMBINE_G2(SS1, SS2, SERVER_SECRET)
    if rtn != 0:
        print "libmpin.MPIN_RECOMBINE_G2( SS1, SS2, SERVER_SECRET) Error %s" % rtn
    if DEBUG:
        print "SERVER_SECRET: %s" % toHex(SERVER_SECRET)

    # Generate client secret shares
    rtn = libmpin.MPIN_GET_CLIENT_SECRET(MS1, HASH_MPIN_ID, CS1)
    if rtn != 0:
        print "libmpin.MPIN_GET_CLIENT_SECRET(MS1,HASH_MPIN_ID,CS1) Error %s" % rtn
    rtn = libmpin.MPIN_GET_CLIENT_SECRET(MS2, HASH_MPIN_ID, CS2)
    if rtn != 0:
        print "libmpin.MPIN_GET_CLIENT_SECRET(MS2,HASH_MPIN_ID,CS2) Error %s" % rtn
    if DEBUG:
        print "CS1: %s" % toHex(CS1)
        print "CS2: %s" % toHex(CS2)

    # Combine client secret shares : TOKEN is the full client secret
    rtn = libmpin.MPIN_RECOMBINE_G1(CS1, CS2, TOKEN)
    if rtn != 0:
        print "libmpin.MPIN_RECOMBINE_G1( CS1, CS2, TOKEN) Error %s" % rtn
    print "Client Secret: %s" % to_hex(TOKEN)

    # Generate Time Permit shares
    if DEBUG:
        print "Date %s" % date
    rtn = libmpin.MPIN_GET_CLIENT_PERMIT(date, MS1, HASH_MPIN_ID, TP1)
    if rtn != 0:
        print "libmpin.MPIN_GET_CLIENT_PERMIT(date,MS1,HASH_MPIN_ID,TP1) Error %s" % rtn
    rtn = libmpin.MPIN_GET_CLIENT_PERMIT(date, MS2, HASH_MPIN_ID, TP2)
    if rtn != 0:
        print "libmpin.MPIN_GET_CLIENT_PERMIT(date,MS2,HASH_MPIN_ID,TP2) Error %s" % rtn
    if DEBUG:
        print "TP1: %s" % to_hex(TP1)
        print "TP2: %s" % to_hex(TP2)

    # Combine Time Permit shares
    rtn = libmpin.MPIN_RECOMBINE_G1(TP1, TP2, TIME_PERMIT)
    if rtn != 0:
        print "libmpin.MPIN_RECOMBINE_G1(TP1, TP2, TIME_PERMIT) Error %s" % rtn
    if DEBUG:
        print "TIME_PERMIT: %s" % to_hex(TIME_PERMIT)

    # Client extracts PIN from secret to create Token
    if INPUT:
        PIN = int(raw_input("Please enter four digit PIN to create M-Pin Token:"))
    else:
        PIN = 1234
    rtn = libmpin.MPIN_EXTRACT_PIN(MPIN_ID, PIN, TOKEN)
    if rtn != 0:
        print "libmpin.MPIN_EXTRACT_PIN( MPIN_ID, PIN, TOKEN) Error %s" % rtn
    print "Token: %s" % to_hex(TOKEN)

    if SINGLE_PASS:
        print "M-Pin Single Pass"
        if INPUT:
            PIN = int(raw_input("Please enter PIN to authenticate:"))
        else:
            PIN = 1234
        TimeValue = libmpin.MPIN_GET_TIME()
        if DEBUG:
            print "TimeValue %s" % TimeValue

        # Client precomputation
        if MPIN_FULL:
            libmpin.MPIN_PRECOMPUTE(TOKEN, HASH_MPIN_ID, TATE1, TATE2)

        # Client MPIN
        rtn = libmpin.MPIN_CLIENT(date, MPIN_ID, RNG, X, PIN, TOKEN, SEC, U, UT, TIME_PERMIT, ffi.NULL, TimeValue, Y)
        if rtn != 0:
            print "MPIN_CLIENT ERROR %s" % rtn
        if DEBUG:
            print "X: %s" % to_hex(X)

        # Client sends Z=r.ID to Server
        if MPIN_FULL:
            libmpin.MPIN_GET_G1_MULTIPLE(RNG, 1, R, HASH_MPIN_ID, Z)

        # Server MPIN
        rtn = libmpin.MPIN_SERVER(date, HID, HTID, Y, SERVER_SECRET, U, UT, SEC, E, F, pID, ffi.NULL, TimeValue)
        if rtn != 0:
            print "ERROR: Single Pass %s is not authenticated" % identity
            if PIN_ERROR:
                err = libmpin.MPIN_KANGAROO(E, F)
                print "Client PIN error %d " % err
        else:
            print "SUCCESS: Single Pass %s is authenticated" % identity

        # Server sends T=w.ID to client
        if MPIN_FULL:
            libmpin.MPIN_GET_G1_MULTIPLE(RNG, 0, W, prHID, T)
            print "T: %s" % to_hex(T)

        if MPIN_FULL:
            libmpin.MPIN_HASH_ALL(prHID,U,UT,SEC,Y,Z,T,HM);
            
            libmpin.MPIN_CLIENT_KEY(TATE1, TATE2, PIN, R, X, HM, T, CK)
            print "Client AES Key: %s" % to_hex(CK)

            libmpin.MPIN_SERVER_KEY(Z, SERVER_SECRET, W, HM, HID, U, UT, SK)
            print "Server AES Key: %s" % to_hex(SK)

    else:
        print "M-Pin Multi Pass"
        if INPUT:
            PIN = int(raw_input("Please enter PIN to authenticate:"))
        else:
            PIN = 1234
        if MPIN_FULL:
            rtn = libmpin.MPIN_PRECOMPUTE(TOKEN, HASH_MPIN_ID, TATE1, TATE2)
            if rtn != 0:
                print "MPIN_PERCOMPUTE  ERROR %s" % rtn

        # Client first pass
        rtn = libmpin.MPIN_CLIENT_1(date, MPIN_ID, RNG, X, PIN, TOKEN, SEC, U, UT, TIME_PERMIT)
        if rtn != 0:
            print "MPIN_CLIENT_1  ERROR %s" % rtn
        if DEBUG:
            print "X: %s" % to_hex(X)

        # Server calculates H(ID) and H(T|H(ID)) (if time permits enabled),
        # and maps them to points on the curve HID and HTID resp.
        libmpin.MPIN_SERVER_1(date, pID, HID, HTID)

        # Server generates Random number Y and sends it to Client
        rtn = libmpin.MPIN_RANDOM_GENERATE(RNG, Y)
        if rtn != 0:
            print "libmpin.MPIN_RANDOM_GENERATE(RNG,Y) Error %s" % rtn
        if DEBUG:
            print "Y: %s" % to_hex(Y)

        # Client second pass
        rtn = libmpin.MPIN_CLIENT_2(X, Y, SEC)
        if rtn != 0:
            print "libmpin.MPIN_CLIENT_2(X,Y,SEC) Error %s" % rtn
        if DEBUG:
            print "V: %s" % to_hex(SEC)

        # Server second pass
        rtn = libmpin.MPIN_SERVER_2(date, HID, HTID, Y, SERVER_SECRET, U, UT, SEC, E, F)
        if rtn != 0:
            print "ERROR: Multi Pass %s is not authenticated" % identity
            if PIN_ERROR:
                err = libmpin.MPIN_KANGAROO(E, F)
                print "Client PIN error %d " % err
        else:
            print "SUCCESS: Multi Pass %s is authenticated" % identity

        # Client sends Z=r.ID to Server
        if MPIN_FULL:
            rtn = libmpin.MPIN_GET_G1_MULTIPLE(RNG, 1, R, HASH_MPIN_ID, Z)
            if rtn != 0:
                print "ERROR: Generating Z %s" % rtn

        # Server sends T=w.ID to client
        if MPIN_FULL:
            rtn = libmpin.MPIN_GET_G1_MULTIPLE(RNG, 0, W, prHID, T)
            if rtn != 0:
                print "ERROR: Generating T %s" % rtn

            libmpin.MPIN_HASH_ALL(HASH_MPIN_ID,U,UT,SEC,Y,Z,T,HM);                

            rtn = libmpin.MPIN_CLIENT_KEY(TATE1, TATE2, PIN, R, X, HM, T, CK)
            if rtn != 0:
                print "ERROR: Generating CK %s" % rtn
            print "Client AES Key: %s" % to_hex(CK)

            rtn = libmpin.MPIN_SERVER_KEY(Z, SERVER_SECRET, W, HM, HID, U, UT, SK)
            if rtn != 0:
                print "ERROR: Generating SK %s" % rtn
            print "Server AES Key: %s" % to_hex(SK)
