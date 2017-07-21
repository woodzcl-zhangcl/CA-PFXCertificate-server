/* cs_rsa_crypt.cpp -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#include "cs_rsa_crypt.h"

#include <openssl/evp.h>
#include <evp_int.h>
#include <openssl/pkcs7.h>
#include <openssl/rc4.h>


cs_rsa_crypt::cs_rsa_crypt(void)
{ 
}


cs_rsa_crypt::~cs_rsa_crypt(void)
{
}

bool cs_rsa_crypt::rc4_encrypt(const char* cleartext, size_t len, const char* pass, size_t s_t_passlen, char* out)
{
	if (!cleartext || 0>=len || !pass || 0>=s_t_passlen)
	{
		return false;
	}
	RC4_KEY rc4key;
	RC4_set_key(&rc4key, (int)s_t_passlen, (const unsigned char*)pass);
	RC4(&rc4key, len, (const unsigned char*)cleartext, (unsigned char*)out);

	return true;
}

bool cs_rsa_crypt::rc4_decrypt(const char* ciphertext, size_t len, const char* pass, size_t s_t_passlen, char* out)
{
	if (!ciphertext || 0>=len || !pass || 0>=s_t_passlen)
	{
		return false;
	}
	RC4_KEY rc4key;
	RC4_set_key(&rc4key, (int)s_t_passlen, (const unsigned char*)pass);
	RC4(&rc4key, len, (const unsigned char*)ciphertext, (unsigned char*)out);

	return true;
}

size_t cs_rsa_crypt::getLengthOfPadding()
{
	return 11;
}

size_t cs_rsa_crypt::getLengthOfBytes(RSA* rsa)
{
	size_t s_tLen = 0;
	if (rsa)
	{
		s_tLen = (size_t)RSA_size(rsa);
	}

	return s_tLen;
}

size_t cs_rsa_crypt::getLengthOfBytes(X509* x509)
{
	size_t s_tLen = 0;
	EVP_PKEY* pKey = X509_get_pubkey(x509);
	if (pKey)
	{
		s_tLen = (size_t)RSA_size(pKey->pkey.rsa);
		EVP_PKEY_free(pKey);
	}

	return s_tLen;
}

size_t cs_rsa_crypt::getLengthOfBytes(PKCS12* p12, const char* pass)
{
	size_t s_tLen = 0;
	EVP_PKEY* pKey = 0;
	X509* x509 = 0;
	if(1==PKCS12_parse(p12, pass, &pKey, &x509, 0))
	{
		if (pKey)
		{
			EVP_PKEY_free(pKey);
		}
		if (x509)
		{
			EVP_PKEY* pKey = X509_get_pubkey(x509);
			if (pKey)
			{
				s_tLen = (size_t)RSA_size(pKey->pkey.rsa);
				EVP_PKEY_free(pKey);
			}
			X509_free(x509);
		}
	}

	return s_tLen;
}

int cs_rsa_crypt::public_encrypt(RSA* rsa, size_t len, const char* in, char* out)
{
	if (!rsa || 0>=len || !in || !out)
	{
		return false;
	}
	int retLen = RSA_public_encrypt((int)len, (unsigned char*)in, (unsigned char*)out, rsa, RSA_PKCS1_PADDING);

	return retLen;
}

int cs_rsa_crypt::private_decrypt(RSA* rsa, size_t len, const char* in, char* out)
{
	if (!rsa || 0>=len || !in || !out)
	{
		return false;
	}
	int retLen = RSA_private_decrypt((int)len, (unsigned char*)in, (unsigned char*)out, rsa, RSA_PKCS1_PADDING);
	
	return retLen;
}

int cs_rsa_crypt::private_encrypt(RSA* rsa, size_t len, const char* in, char* out)
{
	if (!rsa || 0>=len || !in || !out)
	{
		return false;
	}
	int retLen = RSA_private_encrypt((int)len, (unsigned char*)in, (unsigned char*)out, rsa, RSA_PKCS1_PADDING);
	
	return retLen;
}

int cs_rsa_crypt::public_decrypt(RSA* rsa, size_t len, const char* in, char* out)
{
	if (!rsa || 0>=len || !in || !out)
	{
		return false;
	}
	int retLen = RSA_public_decrypt((int)len, (unsigned char*)in, (unsigned char*)out, rsa, RSA_PKCS1_PADDING);
	
	return retLen;
}

int cs_rsa_crypt::public_encrypt(X509* x509, size_t len, const char* in, char* out)
{
	EVP_PKEY* pKey = X509_get_pubkey(x509);
	if (pKey)
	{
		int retLen = public_encrypt(pKey->pkey.rsa, len, in, out);
		EVP_PKEY_free(pKey);
		return retLen;
	}

	return 0;
}

int cs_rsa_crypt::public_decrypt(X509* x509, size_t len, const char* in, char* out)
{
	EVP_PKEY* pKey = X509_get_pubkey(x509);
	if (pKey)
	{
		int retLen = public_decrypt(pKey->pkey.rsa, len, in, out);
		EVP_PKEY_free(pKey);
		return retLen;
	}

	return 0;
}

int cs_rsa_crypt::public_encrypt_nocheck(PKCS12* p12, const char* pass, size_t len, const char* in, char* out)
{
	EVP_PKEY* prikey = 0;
	X509* x509 = 0;
	if(1==PKCS12_parse(p12, pass, &prikey, &x509, 0))
	{
		if (prikey)
		{
			EVP_PKEY_free(prikey);
		}
		if (x509)
		{
			int retLen = public_encrypt(x509, len, in, out);
			X509_free(x509);
			return retLen;
		}
	}

	return 0;
}

int cs_rsa_crypt::private_decrypt_nocheck(PKCS12* p12, const char* pass, size_t len, const char* in, char* out)
{
	EVP_PKEY* prikey = 0;
	X509* x509 = 0;
	if(1==PKCS12_parse(p12, pass, &prikey, &x509, 0))
	{
		if (prikey)
		{
			int retLen = private_decrypt(prikey->pkey.rsa, len, in, out);
			EVP_PKEY_free(prikey);
			return retLen;
		}
		if (x509)
		{
			X509_free(x509);
		}
	}

	return 0;
}

int cs_rsa_crypt::private_encrypt_nocheck(PKCS12* p12, const char* pass, size_t len, const char* in, char* out)
{
	EVP_PKEY* prikey = 0;
	X509* x509 = 0;
	if(1==PKCS12_parse(p12, pass, &prikey, &x509, 0))
	{
		if (prikey)
		{
			int retLen = private_encrypt(prikey->pkey.rsa, len, in, out);
			EVP_PKEY_free(prikey);
			return retLen;
		}
		if (x509)
		{
			X509_free(x509);
		}
	}

	return 0;
}

int cs_rsa_crypt::public_decrypt_nocheck(PKCS12* p12, const char* pass, size_t len, const char* in, char* out)
{
	EVP_PKEY* prikey = 0;
	X509* x509 = 0;
	if(1==PKCS12_parse(p12, pass, &prikey, &x509, 0))
	{
		if (prikey)
		{
			EVP_PKEY_free(prikey);
		}
		if (x509)
		{
			int retLen = public_decrypt(x509, len, in, out);
			X509_free(x509);
			return retLen;
		}
	}

	return 0;
}
