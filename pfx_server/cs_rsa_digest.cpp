/* cs_rsa_digest.cpp -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#include "cs_rsa_digest.h"

#include <string.h>


cs_rsa_digest::cs_rsa_digest(void)
{
	mdctx = 0;
	md = 0;
	memset(uc_digest, 0, sizeof(uc_digest));
	ui_digest_len = 0;
}


cs_rsa_digest::~cs_rsa_digest(void)
{
	if (mdctx)
	{
		EVP_MD_CTX_destroy(mdctx);
	}
}

bool cs_rsa_digest::init(const char* digestID_str)
{
	if (mdctx)
	{
		EVP_MD_CTX_destroy(mdctx);
		mdctx = 0;
	}
	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
	{
		return false;
	}
	EVP_MD_CTX_init(mdctx);
	md = EVP_get_digestbyname(digestID_str);
	if (!md)
	{
		return false;
	}
	if (1!=EVP_DigestInit_ex(mdctx, md, 0))
	{
		return false;
	}

	return true;
}

bool cs_rsa_digest::update(const char* s, size_t len)
{
	if (1!=EVP_DigestUpdate(mdctx, s, len))
	{
		return false;
	}

	return true;
}

bool cs_rsa_digest::final()
{
	if (1!=EVP_DigestFinal_ex(mdctx, uc_digest, &ui_digest_len))
	{
		return false;
	}
	else
	{
		if (mdctx)
		{
			EVP_MD_CTX_destroy(mdctx);
		}
		mdctx = 0;
		md = 0;
	}

	return true;
}
