/* cs_rsa_digest.h -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#ifndef _CS_RSA_DIGEST_
#define _CS_RSA_DIGEST_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <evp_locl.h>

class cs_rsa_digest
{
	EVP_MD_CTX* mdctx;
	const EVP_MD* md;
public:
	unsigned char uc_digest[EVP_MAX_MD_SIZE];
	unsigned int ui_digest_len;
public:
	cs_rsa_digest(void);
	~cs_rsa_digest(void);
public:
	//md4 md5 sha1 sha256 sha384 sha512
	bool init(const char* digestID_str);
	bool update(const char* s, size_t len);
	bool final();
};

#endif
