/* cs_rsa_key.h -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#ifndef _CS_RSA_KEY_
#define _CS_RSA_KEY_

#include <stdio.h>
#include <stdlib.h>

#include "c_util.h"
#include <openssl/rsa.h>

class cs_rsa_key
{
	RSA* m_rsa;
	bool m_bDel;
	CMemBlock<char> m_n;
	CMemBlock<char> m_e;
	CMemBlock<char> m_d;
	CMemBlock<char> m_p;
	CMemBlock<char> m_q;
	CMemBlock<char> m_dmp1;
	CMemBlock<char> m_dmq1;
	CMemBlock<char> m_iqmp;
public:
	cs_rsa_key(void);
	cs_rsa_key(RSA* rsa);
	~cs_rsa_key(void);
public:
	operator bool()const;
	operator RSA*()const;
public:
	bool genKey(int RSAKeyBits=1024, unsigned long e=RSA_F4);
	RSA* create(int RSAKeyBits=1024, unsigned long e=RSA_F4);
	EVP_PKEY* create_evp(int RSAKeyBits=1024, unsigned long e=RSA_F4);
	EVP_PKEY* create_evp(CMemBlock<char> n, CMemBlock<char> e, CMemBlock<char> d, CMemBlock<char> p, CMemBlock<char> q, CMemBlock<char> dmp1, CMemBlock<char> dmq1, CMemBlock<char> iqmp);
public:
	bool setBigNum(CMemBlock<char> n, CMemBlock<char> e, CMemBlock<char> d, CMemBlock<char> p, CMemBlock<char> q, CMemBlock<char> dmp1, CMemBlock<char> dmq1, CMemBlock<char> iqmp);
	bool getBigNum(CMemBlock<char>& n, CMemBlock<char>& e, CMemBlock<char>& d, CMemBlock<char>& p, CMemBlock<char>& q, CMemBlock<char>& dmp1, CMemBlock<char>& dmq1, CMemBlock<char>& iqmp)const;
};

#endif
