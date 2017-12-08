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

#include "amcl.h"
#include "rsa_2048.h"
#include "rsa_3072.h"
#include "rsa_4096.h"
#include "rsa_support.h"

extern int _PKCS15(int h, octet m, octet w);
extern int _OAEP_ENCODE(int h, octet m, csprng* rng, octet p, octet f);
extern int _OAEP_DECODE(int h, octet p, octet f);
extern void _CREATE_CSPRNG(csprng* R, octet S);
extern void _RSA_2048_DECRYPT(rsa_private_key_2048* priv, octet G, octet F);
extern void _RSA_3072_DECRYPT(rsa_private_key_3072* priv, octet G, octet F);
extern void _RSA_4096_DECRYPT(rsa_private_key_4096* priv, octet G, octet F);
extern void _RSA_2048_ENCRYPT(rsa_public_key_2048* pub, octet F, octet G);
extern void _RSA_3072_ENCRYPT(rsa_public_key_3072* pub, octet F, octet G);
extern void _RSA_4096_ENCRYPT(rsa_public_key_4096* pub, octet F, octet G);
extern void _RSA_2048_KEY_PAIR(csprng* rng, sign32 e, rsa_private_key_2048* priv, rsa_public_key_2048* pub, octet p, octet q);
extern void _RSA_3072_KEY_PAIR(csprng* rng, sign32 e, rsa_private_key_3072* priv, rsa_public_key_3072* pub, octet p, octet q);
extern void _RSA_4096_KEY_PAIR(csprng* rng, sign32 e, rsa_private_key_4096* priv, rsa_public_key_4096* pub, octet p, octet q);
extern void _RSA_2048_PRIVATE_KEY_KILL(rsa_private_key_2048* PRIV);
extern void _RSA_3072_PRIVATE_KEY_KILL(rsa_private_key_3072* PRIV);
extern void _RSA_4096_PRIVATE_KEY_KILL(rsa_private_key_4096* PRIV);
extern int _MPIN_BLS383_CLIENT_1(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet S, octet U, octet UT, octet TP);
extern int _MPIN_BN254_CLIENT_1(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet S, octet U, octet UT, octet TP);
extern int _MPIN_BN254CX_CLIENT_1(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet S, octet U, octet UT, octet TP);
extern int _MPIN_BLS383_CLIENT_2(octet x, octet y, octet V);
extern int _MPIN_BN254_CLIENT_2(octet x, octet y, octet V);
extern int _MPIN_BN254CX_CLIENT_2(octet x, octet y, octet V);
extern int _MPIN_BLS383_CLIENT_KEY(int h, octet g1, octet g2, int pin, octet r, octet x, octet p, octet T, octet K);
extern int _MPIN_BN254_CLIENT_KEY(int h, octet g1, octet g2, int pin, octet r, octet x, octet p, octet T, octet K);
extern int _MPIN_BN254CX_CLIENT_KEY(int h, octet g1, octet g2, int pin, octet r, octet x, octet p, octet T, octet K);
extern int _MPIN_BLS383_CLIENT(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet V, octet U, octet UT, octet TP, octet MESSAGE, int t, octet y);
extern int _MPIN_BN254_CLIENT(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet V, octet U, octet UT, octet TP, octet MESSAGE, int t, octet y);
extern int _MPIN_BN254CX_CLIENT(int h, int d, octet ID, csprng* R, octet x, int pin, octet T, octet V, octet U, octet UT, octet TP, octet MESSAGE, int t, octet y);
extern int _MPIN_BLS383_EXTRACT_PIN(int h, octet ID, int pin, octet CS);
extern int _MPIN_BN254_EXTRACT_PIN(int h, octet ID, int pin, octet CS);
extern int _MPIN_BN254CX_EXTRACT_PIN(int h, octet ID, int pin, octet CS);
extern int _MPIN_BLS383_GET_CLIENT_PERMIT(int h, int d, octet S, octet ID, octet TP);
extern int _MPIN_BN254_GET_CLIENT_PERMIT(int h, int d, octet S, octet ID, octet TP);
extern int _MPIN_BN254CX_GET_CLIENT_PERMIT(int h, int d, octet S, octet ID, octet TP);
extern int _MPIN_BLS383_GET_CLIENT_SECRET(octet S, octet ID, octet CS);
extern int _MPIN_BN254_GET_CLIENT_SECRET(octet S, octet ID, octet CS);
extern int _MPIN_BN254CX_GET_CLIENT_SECRET(octet S, octet ID, octet CS);
extern int _MPIN_BLS383_GET_DVS_KEYPAIR(csprng* R, octet Z, octet Pa);
extern int _MPIN_BN254_GET_DVS_KEYPAIR(csprng* R, octet Z, octet Pa);
extern int _MPIN_BN254CX_GET_DVS_KEYPAIR(csprng* R, octet Z, octet Pa);
extern int _MPIN_BLS383_GET_G1_MULTIPLE(csprng* R, int type, octet x, octet G, octet W);
extern int _MPIN_BN254_GET_G1_MULTIPLE(csprng* R, int type, octet x, octet G, octet W);
extern int _MPIN_BN254CX_GET_G1_MULTIPLE(csprng* R, int type, octet x, octet G, octet W);
extern int _MPIN_BLS383_GET_SERVER_SECRET(octet S, octet SS);
extern int _MPIN_BN254_GET_SERVER_SECRET(octet S, octet SS);
extern int _MPIN_BN254CX_GET_SERVER_SECRET(octet S, octet SS);
extern int _MPIN_BLS383_KANGAROO(octet E, octet F);
extern int _MPIN_BN254_KANGAROO(octet E, octet F);
extern int _MPIN_BN254CX_KANGAROO(octet E, octet F);
extern int _MPIN_BLS383_PRECOMPUTE(octet T, octet ID, octet CP, octet g1, octet g2);
extern int _MPIN_BN254_PRECOMPUTE(octet T, octet ID, octet CP, octet g1, octet g2);
extern int _MPIN_BN254CX_PRECOMPUTE(octet T, octet ID, octet CP, octet g1, octet g2);
extern int _MPIN_BLS383_RANDOM_GENERATE(csprng* R, octet S);
extern int _MPIN_BN254_RANDOM_GENERATE(csprng* R, octet S);
extern int _MPIN_BN254CX_RANDOM_GENERATE(csprng* R, octet S);
extern int _MPIN_BLS383_RECOMBINE_G1(octet Q1, octet Q2, octet Q);
extern int _MPIN_BN254_RECOMBINE_G1(octet Q1, octet Q2, octet Q);
extern int _MPIN_BN254CX_RECOMBINE_G1(octet Q1, octet Q2, octet Q);
extern int _MPIN_BLS383_RECOMBINE_G2(octet P1, octet P2, octet P);
extern int _MPIN_BN254_RECOMBINE_G2(octet P1, octet P2, octet P);
extern int _MPIN_BN254CX_RECOMBINE_G2(octet P1, octet P2, octet P);
extern int _MPIN_BLS383_SERVER_2(int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet Pa);
extern int _MPIN_BN254_SERVER_2(int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet Pa);
extern int _MPIN_BN254CX_SERVER_2(int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet Pa);
extern int _MPIN_BLS383_SERVER_KEY(int h, octet Z, octet SS, octet w, octet p, octet I, octet U, octet UT, octet K);
extern int _MPIN_BN254_SERVER_KEY(int h, octet Z, octet SS, octet w, octet p, octet I, octet U, octet UT, octet K);
extern int _MPIN_BN254CX_SERVER_KEY(int h, octet Z, octet SS, octet w, octet p, octet I, octet U, octet UT, octet K);
extern int _MPIN_BLS383_SERVER(int h, int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet ID, octet MESSAGE, int t, octet Pa);
extern int _MPIN_BN254_SERVER(int h, int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet ID, octet MESSAGE, int t, octet Pa);
extern int _MPIN_BN254CX_SERVER(int h, int d, octet HID, octet HTID, octet y, octet SS, octet U, octet UT, octet V, octet E, octet F, octet ID, octet MESSAGE, int t, octet Pa);
extern void _MPIN_BLS383_SERVER_1(int h, int d, octet ID, octet HID, octet HTID);
extern void _MPIN_BN254_SERVER_1(int h, int d, octet ID, octet HID, octet HTID);
extern void _MPIN_BN254CX_SERVER_1(int h, int d, octet ID, octet HID, octet HTID);

