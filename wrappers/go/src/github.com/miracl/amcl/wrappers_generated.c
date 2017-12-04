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
#include "rsa_2048.h"
#include "rsa_3072.h"
#include "rsa_4096.h"
#include "rsa_support.h"
#include "randapi.h"


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

