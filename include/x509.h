/**
 * @file x509.h
 * @author Mike Scott
 * @author Kealan McCusker
 * @date 19th May 2015
 * @brief X509 function Header File
 *
 * @section LICENSE
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

#ifndef X509_H
#define X509_H

/**
	@brief Public key type
*/
typedef struct
{
    int type;  /**< signature type (ECC or RSA) */
    int hash;  /**< hash type */
    int curve; /**< elliptic curve used  */
} pktype;

/* X.509 functions */

/** @brief Extract certificate signature
 *  
 *  Extract certificate signature.
 *
 *	@param c an X.509 signed certificate
 *	@param s the extracted signature
 *	@return 0 on failure, or indicator of signature type (ECC or RSA)
 *  @note Note that signature type is not provided here, its the type of the public key that is
 *        used to verify it that matters, and which determines for example the curve to be used!
 */
extern pktype X509_extract_cert_sig(octet *c,octet *s);

/** @brief Extract certificate from signed certificate
 *
 *  Extract certificate from signed certificate.
 *
 *	@param sc a signed certificate
 *	@param c the extracted certificate
 *	@return 0 on failure
 */
extern int X509_extract_cert(octet *sc,octet *c);

/** @brief Extract public key from certificate
 *
 *  Extract public key from certificate.
 *
 *	@param c an X.509 certificate
 *	@param k the extracted key
 *	@return 0 on failure, or indicator of public key type (ECC or RSA)
 */
extern pktype X509_extract_public_key(octet *c,octet *k);

/** @brief Find index to issuer field in a certificate
 *
 *  Find index to issuer field in a certificate.
 *
 *	@param c an X.509 certificate
 *	@return 0 on failure, or pointer to issuer field in cert
 */
extern int X509_find_issuer(octet *c);

/** @brief Find index to validity period field in a certificate
 *
 *  Find index to validity period field in a certificate.
 *
 *	@param c an X.509 certificate
 *	@return 0 on failure, or pointer to validity field in cert
 */
extern int X509_find_validity(octet *c);

/** @brief Get index to subject field in a certificate
 *
 *  Get index to subject field in a certificate.
 *
 *	@param c an X.509 certificate
 *	@return 0 on failure, or pointer to subject field in cert
 */
extern int X509_find_subject(octet *c);

/** @brief Find entity property indicated by SOID
 *
 *  Find entity property indicated by SOID.
 *
 *	@param c an X.509 certificate
 *	@param S is OID of property we are looking for
 *	@param s is a pointer to the section of interest in the cert
 *	@param f is pointer to the length of the property
 *	@return 0 on failure, or pointer to the property
 */
extern int X509_find_entity_property(octet *c,octet *S,int s,int *f);

/** @brief Find start date of certificate validity period
 *
 *  Find start date of certificate validity period.
 *
 *	@param c an X.509 certificate
 *	@param s is a pointer to the start of the validity field
 *	@return 0 on failure, or pointer to the start date
 */
extern int X509_find_start_date(octet *c,int s);

/** @brief Find expiry date of certificate validity period
 *
 *  Find expiry date of certificate validity period.
 *
 *	@param c an X.509 certificate
 *	@param s is a pointer to the start of the validity field
 *	@return 0 on failure, or pointer to the expiry date
 */
extern int X509_find_expiry_date(octet *c,int s);

#endif
