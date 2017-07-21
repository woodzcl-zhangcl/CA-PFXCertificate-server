/* cs_rsa_crypt.h -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#ifndef _CS_RSA_CRYPT_
#define _CS_RSA_CRYPT_

#include <stdio.h>
#include <stdlib.h>

#include "c_util.h"
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

class cs_rsa_crypt
{
public:
	cs_rsa_crypt(void);
	virtual ~cs_rsa_crypt(void);
public:
	bool rc4_encrypt(const char* cleartext, size_t len, const char* pass, size_t s_t_passlen, char* out);
	bool rc4_decrypt(const char* ciphertext, size_t len, const char* pass, size_t s_t_passlen, char* out);
public:
	size_t getLengthOfPadding();
	size_t getLengthOfBytes(RSA* rsa);
	size_t getLengthOfBytes(X509* x509);
	size_t getLengthOfBytes(PKCS12* p12, const char* pass);
public:
	int public_encrypt(RSA* rsa, size_t len, const char* in, char* out);
	int private_decrypt(RSA* rsa, size_t len, const char* in, char* out);
	int private_encrypt(RSA* rsa, size_t len, const char* in, char* out);
	int public_decrypt(RSA* rsa, size_t len, const char* in, char* out);
public:
	int public_encrypt(X509* x509, size_t len, const char* in, char* out);
	int public_decrypt(X509* x509, size_t len, const char* in, char* out);
public:
	int public_encrypt_nocheck(PKCS12* p12, const char* pass, size_t len, const char* in, char* out);
	int private_decrypt_nocheck(PKCS12* p12, const char* pass, size_t len, const char* in, char* out);
	int private_encrypt_nocheck(PKCS12* p12, const char* pass, size_t len, const char* in, char* out);
	int public_decrypt_nocheck(PKCS12* p12, const char* pass, size_t len, const char* in, char* out);
};

#endif
