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
import os

# MPIN Group Size
PGS = 32
# MPIN Field Size
PFS = 32
G1 = 2*PFS + 1
G2 = 4*PFS
GT = 12*PFS
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


def to_hex(octet_value):
    """Converts an octet type into a string

    Add all the values in an octet into an array. This arrays is then
    converted to a string and hex encoded.

    Args::

        octet_value. An octet pointer type

    Returns::

        String

    Raises:
        Exception
    """
    i = 0
    val = []
    while i < octet_value.len:
        val.append(octet_value.val[i])
        i = i+1
    return ''.join(val).encode("hex")

def make_octet(length, value=None):
    """Generates an octet pointer

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

def today():
    """Today's date as days elapsed from the epoch

    Today's date as days elapsed from the epoch. This function uses the system clock
    
    Args::
        
    Returns::
        
        epoch_days: epoch days

    Raises:
        
    """        
    return libmpin.MPIN_today()    

def get_time():
    """Get time elapsed from the epoch

    Time elapsed from the epoch. This function uses the system clock
    
    Args::
        
    Returns::
        
        epoch_time: epoch time

    Raises:
        
    """        
    return libmpin.MPIN_GET_TIME()    

def create_csprng(seed):
    """Make a Cryptographically secure pseudo-random number generator instance

    Make a Cryptographically secure pseudo-random number generator instance
    
    Args::
        
        seed:   random seed value
           
    Returns::
        
        rng: Pointer to cryptographically secure pseudo-random number generator instance

    Raises:
        
    """
    seed_oct, seed_val = make_octet(None,seed)    

    # random number generator
    rng = ffi.new('csprng*')
    libmpin.MPIN_CREATE_CSPRNG(rng, seed_oct)

    return rng


def hash_id(mpin_id):
    """Hash an M-Pin Identity to an octet

    Hash an M-Pin Identity to an octet
    
    Args::
        
        mpin_id:   An octet pointer containing the M-Pin ID
           
    Returns::
        
        hash_mpin_id: octet point to the hash of the M-Pin ID
        hash_mpin_id_val: Data contained in octet
        
    Raises:
        
    """
    # Hash value of mpin_id
    hash_mpin_id, hash_mpin_id_val = make_octet(HASH_BYTES)
    libmpin.MPIN_HASH_ID(mpin_id, hash_mpin_id)

    return hash_mpin_id, hash_mpin_id_val

def random_generate(rng):
    """Generate a random group element

    Generate a random group element
    
    Args::
        
        rng: Pointer to cryptographically secure pseudo-random number generator instance
           
    Returns::

        error_code: error from the C function
        s: A pointer to octet of a random group element
        s_val: Data contained in octet
        
    Raises:
        
    """
    s, s_val = make_octet(PGS)
    error_code = libmpin.MPIN_RANDOM_GENERATE(rng, s)

    return error_code, s, s_val

def get_server_secret(master_secret):
    """Create a server secret in G2 from a master secret

    Create a server secret in G2 from a master secret
    
    Args::
        
        master_secret:   An octet pointer to the master secret
           
    Returns::

        error_code: error from the C function        
        server_secret: A pointer to octet pointer of the server secret
        server_secret_val: Data contained in octet
        
    Raises:
        
    """
    server_secret, server_secret_val  = make_octet(G2)
    error_code = libmpin.MPIN_GET_SERVER_SECRET(master_secret, server_secret)

    return error_code, server_secret, server_secret_val

def recombine_G2(q1,q2):
    """Add two members from the group G1

    Create a server secret in G2 from a master secret
    
    Args::
        
        q1: An input member of G2
        q2: An input member of G2        
           
    Returns::

        error_code: error from the C function        
        q: An output member of G1 = Q1+Q2
        q_val: Data contained in octet
        
    Raises:
        
    """
    q, q_val  = make_octet(G2)
    error_code =  libmpin.MPIN_RECOMBINE_G2(q1, q2, q)

    return error_code, q, q_val

def get_client_secret(master_secret, hash_mpin_id):
    """Create a client secret in G1 from a master secret and the hash of the M-Pin Id

    Create a client secret in G1 from a master secret and the hash of the M-Pin Id
    
    Args::
        
        master_secret:  An octet pointer to the master secret
        hash_mpin_id:   An octet pointer to the hash of the M-Pin ID        
           
    Returns::

        error_code: error from the C function        
        client_secret: Pointer to octet of client secret
        client_secret_val: Data contained in octet
        
    Raises:
        
    """
    client_secret, client_secret_val  = make_octet(G1)
    error_code = libmpin.MPIN_GET_CLIENT_SECRET(master_secret, hash_mpin_id, client_secret)

    return error_code, client_secret, client_secret_val

def recombine_G1(q1,q2):
    """Add two members from the group G1

    Create a server secret in G1 from a master secret
    
    Args::
        
        q1: An input member of G1
        q2: An input member of G1        
           
    Returns::

        error_code: error from the C function        
        q: An output member of G1 = Q1+Q2
        q_val: Data contained in octet
        
    Raises:
        
    """
    q, q_val  = make_octet(G1)
    error_code =  libmpin.MPIN_RECOMBINE_G1(q1, q2, q)

    return error_code, q, q_val

def get_client_permit(epoch_days, master_secret, hash_mpin_id):
    """Create a time permit in G1 from a master secret, hash of the M-Pin Id and epoch days

    Create a time permit in G1 from a master secret, hash of the M-Pin Id and epoch days
    
    Args::
        
        master_secret:  An octet pointer to the master secret
        hash_mpin_id:   An octet pointer to the hash of the M-Pin ID        
           
    Returns::

        error_code: error from the C function        
        time_permit: Pointer to octet of time permit
        time_permit_val: Data contained in octet
        
    Raises:
        
    """
    time_permit, time_permit_val = make_octet(G1)
    error_code = libmpin.MPIN_GET_CLIENT_PERMIT(epoch_days, master_secret, hash_mpin_id, time_permit)

    return error_code, time_permit, time_permit_val

def extract_pin(mpin_id, pin, client_secret):
    """Extract a PIN from client secret

    Extract a PIN from client secret
    
    Args::
        
        mpin_id:   M-Pin ID
        pin:   PIN input by user
        client_secret: User's client secret
           
    Returns::

        error_code: error from the C function        
        token: Result of extracting a PIN from client secret
        
    Raises:
        
    """
    error_code = libmpin.MPIN_EXTRACT_PIN(mpin_id, pin, client_secret)

    return error_code, client_secret

def precompute(token, hash_mpin_id):
    """Precompute values for use by the client side of M-Pin Full

    Precompute values for use by the client side of M-Pin Full
    
    Args::
        
        token:  M-Pin token
        hash_mpin_id: hash of the M-Pin ID
           
    Returns::

        error_code: error from the C function        
        pc1: Precomputed value one 
        pc1_val: Precomputed value one data        
        pc2: Precomputed value two
        pc2_val: Precomputed value two data        

        
    Raises:
        
    """
    pc1, pc1_val = make_octet(GT)
    pc2, pc2_val = make_octet(GT)
    error_code = libmpin.MPIN_PRECOMPUTE(TOKEN, hash_mpin_id, pc1, pc2)

    return error_code, pc1, pc1_val, pc2, pc2_val

def client_1(epoch_date, mpin_id, rng, x, pin, token, time_permit):
    """Perform first pass of the client side of the 2-pass version of the M-Pin protocol

    Perform first pass of the client side of the 2-pass version of the M-Pin protocol. If Time Permits are
    disabled, set epoch_date = 0, and UT is not generated and can be set to NULL.
    If Time Permits are enabled, and PIN error detection is OFF, U is not generated and
    can be set to NULL.	If Time Permits are enabled, and PIN error detection is ON, U
    and UT are both generated.
    
    
    Args::

	epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
	mpin_id: M-Pin ID
	rng: cryptographically secure random number generator
	pin: PIN entered by user
	token: M-Pin token
	time_permit: M-Pin time permit
           
    Returns::

        error_code: error from the C function
        x: Randomly generated integer if R!=NULL, otherwise must be provided as an input
        x_val: x data
	u: u = x.H(ID)
        u_data: u data
	ut: ut = x.(H(ID)+H(epoch_date|H(ID)))
        ut_data: ut data
	v: v = CS+TP, where CS is the reconstructed client secret and TP is the time permit
        v_date: v data        
        
    Raises:
        
    """
    if rng is not None:
        x, x_val = make_octet(PGS)

    u, u_val = make_octet(G1)    
    ut, ut_val = make_octet(G1)
    v, v_val = make_octet(G1)
  
    error_code = libmpin.MPIN_CLIENT_1(epoch_date, mpin_id, rng, x, pin, token, v, u, ut, time_permit)

    return error_code, x, x_val, u, u_val, ut, ut_val, v, v_val,

def client_2(x,y,sec):
    """Perform second pass of the client side of the 3-pass version of the M-Pin protocol

    Perform second pass of the client side of the 3-pass version of the M-Pin protocol
        
    Args::

        x: locally generated random number
        y: random challenge from server        
	sec: CS+TP, where CS is the reconstructed client secret and TP is the time permit
           
    Returns::

        error_code: error from the C function
	v: v = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
        v_date: v data        
        
    Raises:
        
    """
    error_code = libmpin.MPIN_CLIENT_2(x,y,sec)

    return error_code, sec

def client(epoch_date, mpin_id, rng, x, pin, token, time_permit, message, epoch_time):
    """Perform client side of the one-pass version of the M-Pin protocol

    Perform client side of the one-pass version of the M-Pin protocol. If Time Permits are
    disabled, set epoch_date = 0, and UT is not generated and can be set to NULL.
    If Time Permits are enabled, and PIN error detection is OFF, U is not generated and
    can be set to NULL.	If Time Permits are enabled, and PIN error detection is ON, U
    and UT are both generated.
    
    
    Args::

	epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
	mpin_id: M-Pin ID
	rng: cryptographically secure random number generator
	pin: PIN entered by user
	token: M-Pin token
	time_permit: M-Pin time permit
	message: message to be signed
	epoch_time: Epoch time in seconds 
           
    Returns::

        error_code: error from the C function
        x: Randomly generated integer if R!=NULL, otherwise must be provided as an input
        x_val: x data
	u: u = x.H(ID)
        u_data: u data
	ut: ut = x.(H(ID)+H(epoch_date|H(ID)))
        ut_data: ut data
	v: v = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
        v_date: v data        
	y: y = t H(t|U) or y = H(t|UT) if Time Permits enabled
        y_date: y data
        
    Raises:
        
    """
    if rng is not None:
        x, x_val = make_octet(PGS)

    if message is None:
        message = ffi.NULL
        
    u, u_val = make_octet(G1)    
    ut, ut_val = make_octet(G1)
    v, v_val = make_octet(G1)
    y, y_val = make_octet(PGS)
  
    error_code = libmpin.MPIN_CLIENT(epoch_date, mpin_id, rng, x, pin, token, v, u, ut, time_permit, message, epoch_time, y)

    return error_code, x, x_val, u, u_val, ut, ut_val, v, v_val, y, y_val

def get_G1_multiple(rng, type, G):
    """Find a random multiple of a point in G1

    Find a random multiple of a point in G1
    
    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance
        type: determines type of action to be taken
        G: if type=0 a point in G1, else an octet to be mapped to G1
           
    Returns::

        error_code: error from the C function
        x: an output internally randomly generated if rng!=None, otherwise must be provided as an input
        x_val: x data
        W: W = x.G or W = x.M(G), where M(.) is a mapping when type = 0
        W_val: W data
        
    Raises:
        
    """
    x, x_val = make_octet(PGS)
    W, W_val = make_octet(G1)
    error_code = libmpin.MPIN_GET_G1_MULTIPLE(rng, type, x, G, W)

    return error_code, x, x_val, W, W_val

def server_1(epoch_date, mpin_id):
    """Perform first pass of the server side of the 3-pass version of the M-Pin protocol

    Perform first pass of the server side of the 3-pass version of the M-Pin protocol
    If Time Permits are disabled, set epoch_date = 0, and UT and HTID are not generated
    and can be set to NULL. If Time Permits are enabled, and PIN error detection is OFF,
    U and HID are not needed and can be set to NULL. If Time Permits are enabled,
    and PIN error detection is ON, U, UT, HID and HTID are all required.
    
    Args::

	epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
	mpin_id: M-Pin ID or hash of the M-Pin ID in anonymous mode
           
    Returns::

        hid:  H(mpin_id). H is a map to a point on the curve
        hid_val:hid data
        htid: H(mpin_id)+H(epoch_date|H(mpin_id)). H is a map to a point on the curve
        htid_val: htid data
        
    Raises:
        
    """
    htid, htid_val = make_octet(G1)
    hid, hid_val = make_octet(G1)
  
    libmpin.MPIN_SERVER_1(epoch_date, mpin_id, hid, htid)

    return hid, hid_val, htid, htid_val


def server_2(epoch_date, hid, htid, y, server_secret, u, ut, v):
    """Perform third pass on the server side of the 3-pass version of the M-Pin protocol

    Perform server side of the one-pass version of the M-Pin protocol. If Time
    Permits are disabled, set epoch_date = 0, and UT and HTID are not generated and can
    be set to NULL. If Time Permits are enabled, and PIN error detection is OFF,
    U and HID are not needed and can be set to NULL. If Time Permits are enabled,
    and PIN error detection is ON, U, UT, HID and HTID are all required.
    
    Args::

	epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
        hid:  H(mpin_id). H is a map to a point on the curve
        htid: H(mpin_id)+H(epoch_date|H(mpin_id)). H is a map to a point on the curve
        y: locally generated random number        
        server_secret: Server secret
	u: u = x.H(ID)
	ut: ut = x.(H(ID)+H(epoch_date|H(ID)))
	v: v = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
           
    Returns::

        error_code: error from the C function
        e: value to help the Kangaroos to find the PIN error, or NULL if not required
        e_val: e data
        f: value to help the Kangaroos to find the PIN error, or NULL if not required
        f_val: f data
        
    Raises:
        
    """
    e, e_val = make_octet(GT)
    f, f_val = make_octet(GT)
  
    error_code = libmpin.MPIN_SERVER_2(epoch_date, hid, htid, y, server_secret, u, ut, v, e, f)

    return error_code, e, e_val, f, f_val

def server(epoch_date, server_secret, u, ut, v, mpin_id, message, epoch_time):
    """Perform server side of the one-pass version of the M-Pin protocol

    Perform server side of the one-pass version of the M-Pin protocol. If Time
    Permits are disabled, set epoch_date = 0, and UT and HTID are not generated and can
    be set to NULL. If Time Permits are enabled, and PIN error detection is OFF,
    U and HID are not needed and can be set to NULL. If Time Permits are enabled,
    and PIN error detection is ON, U, UT, HID and HTID are all required.
    
    Args::

	epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
        server_secret: Server secret
	u: u = x.H(ID)
	ut: ut = x.(H(ID)+H(epoch_date|H(ID)))
	v: v = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
	mpin_id: M-Pin ID or hash of the M-Pin ID in anonymous mode
	message: message to be signed        
	epoch_time: Epoch time in seconds 
           
    Returns::

        error_code: error from the C function
        hid:  H(mpin_id). H is a map to a point on the curve
        hid_val:hid data
        htid: H(mpin_id)+H(epoch_date|H(mpin_id)). H is a map to a point on the curve
        htid_val: htid data
        e: value to help the Kangaroos to find the PIN error, or NULL if not required
        e_val: e data
        f: value to help the Kangaroos to find the PIN error, or NULL if not required
        f_val: f data
	y: y = t H(t|U) or y = H(t|UT) if Time Permits enabled used for debug
        y_date: y data
        
    Raises:
        
    """
    if message is None:
        message = ffi.NULL

    htid, htid_val = make_octet(G1)
    hid, hid_val = make_octet(G1)
    e, e_val = make_octet(GT)
    f, f_val = make_octet(GT)
    y, y_val = make_octet(PGS)
  
    error_code = libmpin.MPIN_SERVER(epoch_date, hid, htid, y, server_secret, u, ut, v, e, f, mpin_id, message, epoch_time)

    return error_code, hid, hid_val, htid, htid_val, e, e_val, f, f_val, y, y_val


def kangaroo(e,f):
    """Use Kangaroos to find PIN error

    Use Kangaroos to find PIN error
    
    Args::

        e: e a member of the group GT
        f: F a member of the group GT =  E^pin_error 
           
    Returns::

        pin_error: error in PIN or 0 if Kangaroos failed
        
    Raises:
        
    """
    pin_error = libmpin.MPIN_KANGAROO(e, f)

    return pin_error


def hash_all(hash_mpin_id, u, ut, v, y, r, w):
    """Hash the session transcript 

    Hash the session transcript 
    
    Args::

        hash_mpin_id: An octet pointer to the hash of the M-Pin ID        
	u: u = x.H(mpin_id)
	ut: ut = x.(H(ID)+H(epoch_date|H(ID)))
	v: v = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
        y: server challenge         
        r: client part response
        w: server part response
           
    Returns::

        hm: hash of the input values
        hm_data: hm data
        
    Raises:
        
    """
    if ut is None:
        ut = ffi.NULL
    hm, hm_val = make_octet(HASH_BYTES)  
    libmpin.MPIN_HASH_ALL(hash_mpin_id,u,ut,v,y,r,w,hm);

    return hm, hm_val

def client_key(pc1, pc2, pin, r, x, hm, t):
    """Calculate Key on Client side for M-Pin Full

    Calculate Key on Client side for M-Pin Full
    
    Args::

	pc1: precomputed input
	pc2: precomputed input
	pin: PIN number
	r: locally generated random number
	x: locally generated random number
	hm: hash of the protocol transcript
	t: Server-side Diffie-Hellman component
           
    Returns::

        error_code: error code from the C function
        client_aes_key: client AES key
        client_aes_key_val: client_aes_key data
        
    Raises:
        
    """
    client_aes_key, client_aes_key_val = make_octet(PAS)
    error_code = libmpin.MPIN_CLIENT_KEY(pc1, pc2, pin, r, x, hm, t, client_aes_key)

    return error_code, client_aes_key, client_aes_key_val


def server_key(z, server_secret, w, hm, hid, u, ut):
    """Calculate Key on Server side for M-Pin Full

    Calculate Key on Server side for M-Pin Full.Uses UT internally for the
    key calculation or uses U if UT is set to None
    
    Args::

	z: Client-side Diffie-Hellman component
	server_secret: server secret
	w: random number generated by the server
	hm: hash of the protocol transcript
        hid: H(mpin_id). H is a map to a point on the curve
	u: u = x.H(ID)
	ut: ut = x.(H(ID)+H(epoch_date|H(ID)))
           
    Returns::

        error_code: error code from the C function
        server_aes_key: server AES key
        server_aes_key_val: server_aes_key data
        
    Raises:
        
    """
    if ut is None:
        ut =  ffi.NULL
        
    server_aes_key, server_aes_key_val = make_octet(PAS)
    error_code = libmpin.MPIN_SERVER_KEY(z, server_secret, w, hm, hid, u, ut, server_aes_key)

    return error_code, server_aes_key, server_aes_key_val


def aes_gcm_encrypt(aes_key,iv,header,plaintext):
    """AES-GCM Encryption

    AES-GCM Encryption 
    
    Args::

        aes_key: AES Key
	iv: Initializartion vector
	header: header
	plaintext: Plaintext to be encrypted
           
    Returns::
        
        ciphertext: resultant ciphertext
        tag: checksum
        
        
    Raises:
        
    """
    aes_key1, aes_key1_val = make_octet(None,aes_key)
    iv1, iv1_val = make_octet(None,iv)
    header1, header1_val = make_octet(None,header)
    plaintext1, plaintext1_val = make_octet(None,plaintext)        
    tag1, tag1_val = make_octet(PAS)
    ciphertext1, ciphertext1_val = make_octet(len(plaintext))

    libmpin.MPIN_AES_GCM_ENCRYPT(aes_key1, iv1, header1, plaintext1, ciphertext1, tag1)
    tag = to_hex(tag1)
    ciphertext = to_hex(ciphertext1)    

    return ciphertext.decode("hex"), tag.decode("hex")

def aes_gcm_decrypt(aes_key,iv,header,ciphertext):
    """AES-GCM Decryption

    AES-GCM Deryption 
    
    Args::

        aes_key: AES Key
	iv: Initializartion vector
	header: header
        ciphertext: ciphertext
           
    Returns::
        
	plaintext: resultant plaintext
        tag: checksum
                
    Raises:
        
    """
    aes_key1, aes_key1_val = make_octet(None,aes_key)
    iv1, iv1_val = make_octet(None,iv)
    header1, header1_val = make_octet(None,header)
    ciphertext1, ciphertext1_val = make_octet(None,ciphertext)        
    tag1, tag1_val = make_octet(PAS)
    plaintext1, plaintext1_val = make_octet(len(ciphertext))

    libmpin.MPIN_AES_GCM_DECRYPT(aes_key1, iv1, header1, ciphertext1, plaintext1,tag1)
    tag = to_hex(tag1)
    plaintext = to_hex(plaintext1)    

    return plaintext.decode("hex"), tag.decode("hex")

if __name__ == "__main__":
    # Print hex values
    DEBUG = False
    # Require user input
    INPUT = False
    ONE_PASS = True
    TIME_PERMITS = False
    MPIN_FULL = True
    PIN_ERROR = True
    USE_ANONYMOUS = False

    if TIME_PERMITS:
        date = today()
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

    X, X_val = make_octet(PGS)

    # Assign a seed value
    RAW, RAW_val = make_octet(None,seed)
    if DEBUG:
        print "RAW: %s" % to_hex(RAW)

    # random number generator
    # rng = ffi.new("csprng*")
    # libmpin.MPIN_CREATE_CSPRNG(RNG, RAW)
    rng = create_csprng(seed)

    # Hash MPIN_ID
    HASH_MPIN_ID, HASH_MPIN_ID_val = hash_id(MPIN_ID)
    if DEBUG:
        print "MPIN_ID: %s" % to_hex(MPIN_ID)
        print "HASH_MPIN_ID: %s" % to_hex(HASH_MPIN_ID)

    if USE_ANONYMOUS:
        pID = HASH_MPIN_ID
    else:
        pID = MPIN_ID
        
    # Generate master secret for MIRACL and Customer
    rtn,MS1,MS1_val = random_generate(rng)
    if rtn != 0:
        print "random_generate(rng) Error %s", rtn
    rtn,MS2,MS2_val = random_generate(rng)        
    if rtn != 0:
        print "random_generate(rng) Error %s", rtn
    if DEBUG:
        print "MS1: %s" % to_hex(MS1)
        print "MS2: %s" % to_hex(MS2)

    # Generate server secret shares
    rtn,SS1,SS1_val = get_server_secret(MS1)
    if rtn != 0:
        print "get_server_secret(MS1) Error %s" % rtn
    rtn,SS2,SS2_val = get_server_secret(MS2)        
    if rtn != 0:
        print "get_server_secret(MS2) Error %s" % rtn
    if DEBUG:
        print "SS1: %s" % to_hex(SS1)
        print "SS2: %s" % to_hex(SS2)

    # Combine server secret shares
    rtn, SERVER_SECRET, SERVER_SECRET_val = recombine_G2(SS1, SS2)
    if rtn != 0:
        print "recombine_G2(SS1, SS2) Error %s" % rtn
    if DEBUG:
        print "SERVER_SECRET: %s" % to_hex(SERVER_SECRET)

    # Generate client secret shares
    rtn, CS1, CS1_val = get_client_secret(MS1, HASH_MPIN_ID)
    if rtn != 0:
        print "get_client_secret(MS1, HASH_MPIN_ID) Error %s" % rtn
    rtn, CS2, CS2_val = get_client_secret(MS2, HASH_MPIN_ID)
    if rtn != 0:
        print "get_client_secret(MS2, HASH_MPIN_ID) Error %s" % rtn
    if DEBUG:
        print "CS1: %s" % to_hex(CS1)
        print "CS2: %s" % to_hex(CS2)

    # Combine client secret shares : TOKEN is the full client secret
    rtn, TOKEN, TOKEN_val = recombine_G1(CS1, CS2)
    if rtn != 0:
        print "recombine_G1(CS1, CS2) Error %s" % rtn
    print "Client Secret: %s" % to_hex(TOKEN)

    # Generate Time Permit shares
    if DEBUG:
        print "Date %s" % date
    rtn, TP1, TP1_val = get_client_permit(date, MS1, HASH_MPIN_ID)
    if rtn != 0:
        print "get_client_permit(date, MS1, HASH_MPIN_ID) Error %s" % rtn
    rtn, TP2, TP2_val = get_client_permit(date, MS2, HASH_MPIN_ID)
    if rtn != 0:
        print "get_client_permit(date, MS2, HASH_MPIN_ID) Error %s" % rtn
    if DEBUG:
        print "TP1: %s" % to_hex(TP1)
        print "TP2: %s" % to_hex(TP2)

    # Combine Time Permit shares
    rtn, TIME_PERMIT, TIME_PERMIT_val = recombine_G1(TP1, TP2)
    if rtn != 0:
        print "recombine_G1(TP1, TP2) Error %s" % rtn
    if DEBUG:
        print "TIME_PERMIT: %s" % to_hex(TIME_PERMIT)

    # Client extracts PIN from secret to create Token
    if INPUT:
        PIN = int(raw_input("Please enter four digit PIN to create M-Pin Token:"))
    else:
        PIN = 1234
    rtn, TOKEN = extract_pin(MPIN_ID, PIN, TOKEN)
    if rtn != 0:
        print "extract_pin(MPIN_ID, PIN, TOKEN) Error %s" % rtn
    print "Token: %s" % to_hex(TOKEN)

    if ONE_PASS:
        print "M-Pin One Pass"
        if INPUT:
            PIN = int(raw_input("Please enter PIN to authenticate:"))
        else:
            PIN = 1234
        TimeValue = get_time()
        if DEBUG:
            print "TimeValue %s" % TimeValue

        # Client precomputation
        if MPIN_FULL:
            rtn, PC1, PC1_val, PC2, PC2_val = precompute(TOKEN, HASH_MPIN_ID)

        # Client MPIN
        rtn, X, X_val, U, U_val, UT, UT_val, V, V_val, Y, Y_val = client(date, MPIN_ID, rng, X, PIN, TOKEN, TIME_PERMIT, None, TimeValue)
        if rtn != 0:
            print "MPIN_CLIENT ERROR %s" % rtn

        # Client sends Z=r.ID to Server
        if MPIN_FULL:
            rtn, R, R_val, Z, Z_val = get_G1_multiple(rng, 1, HASH_MPIN_ID)

        # Server MPIN
        rtn, HID, HID_val, HTID, HTID_val, E, E_val, F, F_val, Y2, Y2_val = server(date, SERVER_SECRET, U, UT, V, pID, None, TimeValue)
        if rtn != 0:
            print "ERROR: Single Pass %s is not authenticated" % identity
            if PIN_ERROR:
                err = kangaroo(E, F)
                print "Client PIN error %d " % err
            raise SystemExit, 0
        else:
            print "SUCCESS: %s is authenticated" % identity

        if date:
            prHID = HTID
        else:
            prHID = HID
            UT = None

        # Server sends T=w.ID to client
        if MPIN_FULL:
            rtn, W, W_val, T, T_val = get_G1_multiple(rng, 0, prHID)
            if rtn != 0:
                print "ERROR: Generating T %s" % rtn

        if MPIN_FULL:
            HM, HM_val = hash_all(HASH_MPIN_ID,U,UT,V,Y,R,W)
            
            rtn, CK, CK_val = client_key(PC1, PC2, PIN, R, X, HM, T)
            if rtn != 0:
                print "ERROR: Generating CK %s" % rtn            
            print "Client AES Key: %s" % to_hex(CK)

            rtn, SK, SK_val = server_key(Z, SERVER_SECRET, W, HM, HID, U, UT)
            if rtn != 0:
                print "ERROR: Generating SK %s" % rtn            
            print "Server AES Key: %s" % to_hex(SK)

    else:
        print "M-Pin Three Pass"
        if INPUT:
            PIN = int(raw_input("Please enter PIN to authenticate:"))
        else:
            PIN = 1234
        if MPIN_FULL:
            rtn, PC1, PC1_val, PC2, PC2_val = precompute(TOKEN, HASH_MPIN_ID)
            if rtn != 0:
                print "precompute(TOKEN, HASH_MPIN_ID) ERROR %s" % rtn

        # Client first pass
        rtn, X, X_val, U, U_val, UT, UT_val, SEC, SEC_val = client_1(date, MPIN_ID, rng, X, PIN, TOKEN, TIME_PERMIT)
        if DEBUG:
            print "X: %s" % to_hex(X)
            print "U: %s" % to_hex(U)
            print "UT: %s" % to_hex(UT)
            print "SEC: %s" % to_hex(SEC)                                
        if rtn != 0:
            print "client_1  ERROR %s" % rtn
        if DEBUG:
            print "X: %s" % to_hex(X)

        # Server calculates H(ID) and H(T|H(ID)) (if time permits enabled),
        # and maps them to points on the curve HID and HTID resp.
        HID, HID_val, HTID, HTID_val = server_1(date, pID)
        if DEBUG:
            print "HID: %s" % to_hex(HID)
            print "HTID: %s" % to_hex(HTID)            

        # Server generates Random number Y and sends it to Client
        rtn, Y, Y_val = random_generate(rng)
        if DEBUG:
            print "X: %s" % to_hex(X)        
        if rtn != 0:
            print "random_generate(rng) Error %s" % rtn
        if DEBUG:
            print "Y: %s" % to_hex(Y)

        # Client second pass
        rtn, V = client_2(X, Y, SEC)
        if DEBUG:
            print "V: %s" % to_hex(V)        
        if rtn != 0:
            print "client_2(X, Y, SEC) Error %s" % rtn

        # Server second pass
        rtn, E, E_val, F, F_val = server_2(date, HID, HTID, Y, SERVER_SECRET, U, UT, V)
        if rtn != 0:
            print "ERROR: Multi Pass %s is not authenticated" % identity
            if PIN_ERROR:
                err = kangaroo(E, F)
                print "Client PIN error %d " % err
            raise SystemExit, 0
        else:
            print "SUCCESS: %s is authenticated" % identity

        # Client sends Z=r.ID to Server
        if MPIN_FULL:
            rtn, R, R_val, Z, Z_val = get_G1_multiple(rng, 1, HASH_MPIN_ID)
            if rtn != 0:
                print "ERROR: Generating Z %s" % rtn

        if date:
            prHID = HTID
        else:
            prHID = HID
            UT = None

        # Server sends T=w.ID to client
        if MPIN_FULL:
            rtn, W, W_val, T, T_val = get_G1_multiple(rng, 0, prHID)
            if rtn != 0:
                print "ERROR: Generating T %s" % rtn

            HM, HM_val = hash_all(HASH_MPIN_ID,U,UT,V,Y,R,W);

            rtn, CK, CK_val = client_key(PC1, PC2, PIN, R, X, HM, T)
            if rtn != 0:
                print "ERROR: Generating CK %s" % rtn
            print "Client AES Key: %s" % to_hex(CK)

            rtn, SK, SK_val = server_key(Z, SERVER_SECRET, W, HM, HID, U, UT)
            if rtn != 0:
                print "ERROR: Generating SK %s" % rtn
            print "Server AES Key: %s" % to_hex(SK)

    client_aes_key_hex = to_hex(CK)
    client_aes_key = client_aes_key_hex.decode("hex")
    print client_aes_key.encode("hex")    
    plaintext = "A test message"
    print plaintext
    header_hex = "1554a69ecbf04e507eb6985a234613246206c85f8af73e61ab6e2382a26f457d";
    header = header_hex.decode("hex")
    print header.encode("hex")
    iv_hex = "2b213af6b0edf6972bf996fb";
    iv = iv_hex.decode("hex")
    print iv.encode("hex")    
    ciphertext, tag = aes_gcm_encrypt(client_aes_key,iv,header,plaintext)
    print "ciphertext ", ciphertext.encode("hex")
    print "tag ", tag.encode("hex")        

    plaintext2, tag2 = aes_gcm_decrypt(client_aes_key,iv,header,ciphertext)
    print "plaintext2 ", plaintext2
    print "tag2 ", tag2.encode("hex")        
