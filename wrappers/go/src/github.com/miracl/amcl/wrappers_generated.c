/*
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
*/

/*
AMCL wrapper function that allow passing octet by value which allows passing
Go byte slices without additional allocations.

WARNING: by passing octets by value you can't assess len and max if they are
changed in the function.
*/

#include "amcl.h"
#include "mpin_BLS383.h"
#include "mpin_BN254.h"
#include "mpin_BN254CX.h"
#include "randapi.h"
#include "rsa_2048.h"
#include "rsa_3072.h"
#include "rsa_4096.h"
#include "rsa_support.h"


int _PKCS15(int h, octet m, octet w)
{
	return PKCS15(h, &m, &w);
}

int _OAEP_ENCODE(int h, octet m, csprng* rng, octet p, octet f)
{
	return OAEP_ENCODE(h, &m, rng, &p, &f);
}

int _OAEP_DECODE(int h, octet p, octet f)
{
	return OAEP_DECODE(h, &p, &f);
}

void _CREATE_CSPRNG(csprng* R, octet S)
{
	CREATE_CSPRNG(R, &S);
}

void _RSA_2048_DECRYPT(rsa_private_key_2048* priv, octet G, octet F)
{
	RSA_2048_DECRYPT(priv, &G, &F);
}

void _RSA_3072_DECRYPT(rsa_private_key_3072* priv, octet G, octet F)
{
	RSA_3072_DECRYPT(priv, &G, &F);
}

void _RSA_4096_DECRYPT(rsa_private_key_4096* priv, octet G, octet F)
{
	RSA_4096_DECRYPT(priv, &G, &F);
}

void _RSA_2048_ENCRYPT(rsa_public_key_2048* pub, octet F, octet G)
{
	RSA_2048_ENCRYPT(pub, &F, &G);
}

void _RSA_3072_ENCRYPT(rsa_public_key_3072* pub, octet F, octet G)
{
	RSA_3072_ENCRYPT(pub, &F, &G);
}

void _RSA_4096_ENCRYPT(rsa_public_key_4096* pub, octet F, octet G)
{
	RSA_4096_ENCRYPT(pub, &F, &G);
}

void _RSA_2048_KEY_PAIR(csprng* rng, sign32 e, rsa_private_key_2048* priv, rsa_public_key_2048* pub, octet p, octet q)
{
	RSA_2048_KEY_PAIR(rng, e, priv, pub, &p, &q);
}

void _RSA_3072_KEY_PAIR(csprng* rng, sign32 e, rsa_private_key_3072* priv, rsa_public_key_3072* pub, octet p, octet q)
{
	RSA_3072_KEY_PAIR(rng, e, priv, pub, &p, &q);
}

void _RSA_4096_KEY_PAIR(csprng* rng, sign32 e, rsa_private_key_4096* priv, rsa_public_key_4096* pub, octet p, octet q)
{
	RSA_4096_KEY_PAIR(rng, e, priv, pub, &p, &q);
}

void _RSA_2048_PRIVATE_KEY_KILL(rsa_private_key_2048* PRIV)
{
	RSA_2048_PRIVATE_KEY_KILL(PRIV);
}

void _RSA_3072_PRIVATE_KEY_KILL(rsa_private_key_3072* PRIV)
{
	RSA_3072_PRIVATE_KEY_KILL(PRIV);
}

void _RSA_4096_PRIVATE_KEY_KILL(rsa_private_key_4096* PRIV)
{
	RSA_4096_PRIVATE_KEY_KILL(PRIV);
}

int _MPIN_BLS383_CLIENT_1(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet S, octet U, octet UT, octet TP)
{
	return MPIN_BLS383_CLIENT_1(h, d, &ID, R, &x, pin, &T, &S, &U, &UT, &TP);
}

int _MPIN_BN254_CLIENT_1(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet S, octet U, octet UT, octet TP)
{
	return MPIN_BN254_CLIENT_1(h, d, &ID, R, &x, pin, &T, &S, &U, &UT, &TP);
}

int _MPIN_BN254CX_CLIENT_1(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet S, octet U, octet UT, octet TP)
{
	return MPIN_BN254CX_CLIENT_1(h, d, &ID, R, &x, pin, &T, &S, &U, &UT, &TP);
}

int _MPIN_BLS383_CLIENT_2(octet x, octet y, octet V)
{
	return MPIN_BLS383_CLIENT_2(&x, &y, &V);
}

int _MPIN_BN254_CLIENT_2(octet x, octet y, octet V)
{
	return MPIN_BN254_CLIENT_2(&x, &y, &V);
}

int _MPIN_BN254CX_CLIENT_2(octet x, octet y, octet V)
{
	return MPIN_BN254CX_CLIENT_2(&x, &y, &V);
}

int _MPIN_BLS383_CLIENT_KEY(int h, octet g1, octet g2, int pin, octet r, octet x, octet p, octet T, octet K)
{
	return MPIN_BLS383_CLIENT_KEY(h, &g1, &g2, pin, &r, &x, &p, &T, &K);
}

int _MPIN_BN254_CLIENT_KEY(int h, octet g1, octet g2, int pin, octet r, octet x, octet p, octet T, octet K)
{
	return MPIN_BN254_CLIENT_KEY(h, &g1, &g2, pin, &r, &x, &p, &T, &K);
}

int _MPIN_BN254CX_CLIENT_KEY(int h, octet g1, octet g2, int pin, octet r, octet x, octet p, octet T, octet K)
{
	return MPIN_BN254CX_CLIENT_KEY(h, &g1, &g2, pin, &r, &x, &p, &T, &K);
}

int _MPIN_BLS383_CLIENT(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet V, octet U, octet UT, octet TP, octet MESSAGE, int t, octet y)
{
	return MPIN_BLS383_CLIENT(h, d, &ID, R, &x, pin, &T, &V, &U, &UT, &TP, &MESSAGE, t, &y);
}

int _MPIN_BN254_CLIENT(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet V, octet U, octet UT, octet TP, octet MESSAGE, int t, octet y)
{
	return MPIN_BN254_CLIENT(h, d, &ID, R, &x, pin, &T, &V, &U, &UT, &TP, &MESSAGE, t, &y);
}

int _MPIN_BN254CX_CLIENT(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet V, octet U, octet UT, octet TP, octet MESSAGE, int t, octet y)
{
	return MPIN_BN254CX_CLIENT(h, d, &ID, R, &x, pin, &T, &V, &U, &UT, &TP, &MESSAGE, t, &y);
}

int _MPIN_BLS383_EXTRACT_PIN(int h, octet ID, int pin, octet CS)
{
	return MPIN_BLS383_EXTRACT_PIN(h, &ID, pin, &CS);
}

int _MPIN_BN254_EXTRACT_PIN(int h, octet ID, int pin, octet CS)
{
	return MPIN_BN254_EXTRACT_PIN(h, &ID, pin, &CS);
}

int _MPIN_BN254CX_EXTRACT_PIN(int h, octet ID, int pin, octet CS)
{
	return MPIN_BN254CX_EXTRACT_PIN(h, &ID, pin, &CS);
}

int _MPIN_BLS383_GET_CLIENT_PERMIT(int h, int d, octet S, octet ID, octet TP)
{
	return MPIN_BLS383_GET_CLIENT_PERMIT(h, d, &S, &ID, &TP);
}

int _MPIN_BN254_GET_CLIENT_PERMIT(int h, int d, octet S, octet ID, octet TP)
{
	return MPIN_BN254_GET_CLIENT_PERMIT(h, d, &S, &ID, &TP);
}

int _MPIN_BN254CX_GET_CLIENT_PERMIT(int h, int d, octet S, octet ID, octet TP)
{
	return MPIN_BN254CX_GET_CLIENT_PERMIT(h, d, &S, &ID, &TP);
}

int _MPIN_BLS383_GET_CLIENT_SECRET(octet S, octet ID, octet CS)
{
	return MPIN_BLS383_GET_CLIENT_SECRET(&S, &ID, &CS);
}

int _MPIN_BN254_GET_CLIENT_SECRET(octet S, octet ID, octet CS)
{
	return MPIN_BN254_GET_CLIENT_SECRET(&S, &ID, &CS);
}

int _MPIN_BN254CX_GET_CLIENT_SECRET(octet S, octet ID, octet CS)
{
	return MPIN_BN254CX_GET_CLIENT_SECRET(&S, &ID, &CS);
}

int _MPIN_BLS383_GET_DVS_KEYPAIR(csprng* R, octet Z, octet Pa)
{
	return MPIN_BLS383_GET_DVS_KEYPAIR(R, &Z, &Pa);
}

int _MPIN_BN254_GET_DVS_KEYPAIR(csprng* R, octet Z, octet Pa)
{
	return MPIN_BN254_GET_DVS_KEYPAIR(R, &Z, &Pa);
}

int _MPIN_BN254CX_GET_DVS_KEYPAIR(csprng* R, octet Z, octet Pa)
{
	return MPIN_BN254CX_GET_DVS_KEYPAIR(R, &Z, &Pa);
}

int _MPIN_BLS383_GET_G1_MULTIPLE(csprng* R, int type, octet x, octet G, octet W)
{
	return MPIN_BLS383_GET_G1_MULTIPLE(R, type, &x, &G, &W);
}

int _MPIN_BN254_GET_G1_MULTIPLE(csprng* R, int type, octet x, octet G, octet W)
{
	return MPIN_BN254_GET_G1_MULTIPLE(R, type, &x, &G, &W);
}

int _MPIN_BN254CX_GET_G1_MULTIPLE(csprng* R, int type, octet x, octet G, octet W)
{
	return MPIN_BN254CX_GET_G1_MULTIPLE(R, type, &x, &G, &W);
}

int _MPIN_BLS383_GET_SERVER_SECRET(octet S, octet SS)
{
	return MPIN_BLS383_GET_SERVER_SECRET(&S, &SS);
}

int _MPIN_BN254_GET_SERVER_SECRET(octet S, octet SS)
{
	return MPIN_BN254_GET_SERVER_SECRET(&S, &SS);
}

int _MPIN_BN254CX_GET_SERVER_SECRET(octet S, octet SS)
{
	return MPIN_BN254CX_GET_SERVER_SECRET(&S, &SS);
}

int _MPIN_BLS383_KANGAROO(octet E, octet F)
{
	return MPIN_BLS383_KANGAROO(&E, &F);
}

int _MPIN_BN254_KANGAROO(octet E, octet F)
{
	return MPIN_BN254_KANGAROO(&E, &F);
}

int _MPIN_BN254CX_KANGAROO(octet E, octet F)
{
	return MPIN_BN254CX_KANGAROO(&E, &F);
}

int _MPIN_BLS383_PRECOMPUTE(octet T, octet ID, octet CP, octet g1, octet g2)
{
	return MPIN_BLS383_PRECOMPUTE(&T, &ID, &CP, &g1, &g2);
}

int _MPIN_BN254_PRECOMPUTE(octet T, octet ID, octet CP, octet g1, octet g2)
{
	return MPIN_BN254_PRECOMPUTE(&T, &ID, &CP, &g1, &g2);
}

int _MPIN_BN254CX_PRECOMPUTE(octet T, octet ID, octet CP, octet g1, octet g2)
{
	return MPIN_BN254CX_PRECOMPUTE(&T, &ID, &CP, &g1, &g2);
}

int _MPIN_BLS383_RANDOM_GENERATE(csprng* R, octet S)
{
	return MPIN_BLS383_RANDOM_GENERATE(R, &S);
}

int _MPIN_BN254_RANDOM_GENERATE(csprng* R, octet S)
{
	return MPIN_BN254_RANDOM_GENERATE(R, &S);
}

int _MPIN_BN254CX_RANDOM_GENERATE(csprng* R, octet S)
{
	return MPIN_BN254CX_RANDOM_GENERATE(R, &S);
}

int _MPIN_BLS383_RECOMBINE_G1(octet Q1, octet Q2, octet Q)
{
	return MPIN_BLS383_RECOMBINE_G1(&Q1, &Q2, &Q);
}

int _MPIN_BN254_RECOMBINE_G1(octet Q1, octet Q2, octet Q)
{
	return MPIN_BN254_RECOMBINE_G1(&Q1, &Q2, &Q);
}

int _MPIN_BN254CX_RECOMBINE_G1(octet Q1, octet Q2, octet Q)
{
	return MPIN_BN254CX_RECOMBINE_G1(&Q1, &Q2, &Q);
}

int _MPIN_BLS383_RECOMBINE_G2(octet P1, octet P2, octet P)
{
	return MPIN_BLS383_RECOMBINE_G2(&P1, &P2, &P);
}

int _MPIN_BN254_RECOMBINE_G2(octet P1, octet P2, octet P)
{
	return MPIN_BN254_RECOMBINE_G2(&P1, &P2, &P);
}

int _MPIN_BN254CX_RECOMBINE_G2(octet P1, octet P2, octet P)
{
	return MPIN_BN254CX_RECOMBINE_G2(&P1, &P2, &P);
}

int _MPIN_BLS383_SERVER_2(int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet Pa)
{
	return MPIN_BLS383_SERVER_2(d, &HID, &HTID, &y, &SS, &U, &UT, &V, &E, &F, &Pa);
}

int _MPIN_BN254_SERVER_2(int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet Pa)
{
	return MPIN_BN254_SERVER_2(d, &HID, &HTID, &y, &SS, &U, &UT, &V, &E, &F, &Pa);
}

int _MPIN_BN254CX_SERVER_2(int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet Pa)
{
	return MPIN_BN254CX_SERVER_2(d, &HID, &HTID, &y, &SS, &U, &UT, &V, &E, &F, &Pa);
}

int _MPIN_BLS383_SERVER_KEY(int h, octet Z, octet SS, octet w, octet p, octet I, octet U, octet UT, octet K)
{
	return MPIN_BLS383_SERVER_KEY(h, &Z, &SS, &w, &p, &I, &U, &UT, &K);
}

int _MPIN_BN254_SERVER_KEY(int h, octet Z, octet SS, octet w, octet p, octet I, octet U, octet UT, octet K)
{
	return MPIN_BN254_SERVER_KEY(h, &Z, &SS, &w, &p, &I, &U, &UT, &K);
}

int _MPIN_BN254CX_SERVER_KEY(int h, octet Z, octet SS, octet w, octet p, octet I, octet U, octet UT, octet K)
{
	return MPIN_BN254CX_SERVER_KEY(h, &Z, &SS, &w, &p, &I, &U, &UT, &K);
}

int _MPIN_BLS383_SERVER(int h, int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet ID, octet MESSAGE, int t, octet Pa)
{
	return MPIN_BLS383_SERVER(h, d, &HID, &HTID, &y, &SS, &U, &UT, &V, &E, &F, &ID, &MESSAGE, t, &Pa);
}

int _MPIN_BN254_SERVER(int h, int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet ID, octet MESSAGE, int t, octet Pa)
{
	return MPIN_BN254_SERVER(h, d, &HID, &HTID, &y, &SS, &U, &UT, &V, &E, &F, &ID, &MESSAGE, t, &Pa);
}

int _MPIN_BN254CX_SERVER(int h, int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet ID, octet MESSAGE, int t, octet Pa)
{
	return MPIN_BN254CX_SERVER(h, d, &HID, &HTID, &y, &SS, &U, &UT, &V, &E, &F, &ID, &MESSAGE, t, &Pa);
}

void _MPIN_BLS383_SERVER_1(int h, int d, octet ID, octet HID, octet HTID)
{
	MPIN_BLS383_SERVER_1(h, d, &ID, &HID, &HTID);
}

void _MPIN_BN254_SERVER_1(int h, int d, octet ID, octet HID, octet HTID)
{
	MPIN_BN254_SERVER_1(h, d, &ID, &HID, &HTID);
}

void _MPIN_BN254CX_SERVER_1(int h, int d, octet ID, octet HID, octet HTID)
{
	MPIN_BN254CX_SERVER_1(h, d, &ID, &HID, &HTID);
}

