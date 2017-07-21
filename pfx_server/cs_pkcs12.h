/* cs_pkcs12.h -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#ifndef _CS_PKCS12_
#define _CS_PKCS12_

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <map>

#include "c_util.h"

#include <openssl/pkcs12.h>

class cs_pkcs12
{
	PKCS12* m_p12;
	bool m_bDel;
public:
	cs_pkcs12(void);
	cs_pkcs12(PKCS12* p12);
	~cs_pkcs12(void);
public:
	operator bool()const;
	operator PKCS12*()const;
public:
	bool setDerP12(const char* derP12, size_t p12Len);
	bool create(const char* pass, EVP_PKEY* prikey, X509* x509, const char* aliasname=0, bool bSign=true);
	bool setpass(const char* oldpass, const char* newpass);
	CMemBlock<char> getDerP12();
	CMemBlock<char> getX509(const char* pass);
};

#endif

