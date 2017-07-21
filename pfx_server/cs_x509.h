/* cs_x509.h -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#ifndef _CS_X509_
#define _CS_X509_

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <map>
#include <time.h>

#include "c_util.h"
#include <openssl/evp.h>  
#include <openssl/x509.h>  

class cs_x509
{
	X509* m_x509;
	bool m_bDel;
public:
	cs_x509(void);
	cs_x509(X509* x509);
	~cs_x509(void);
public:
	operator bool()const;
	operator X509*()const;
public:
	bool setDerCert(const char *derCert, size_t certLen);
	CMemBlock<char> getDerCert();
public:
	long get_version();
	CMemBlock<char> get_serial();
private:
	CMemBlock<char> get_text_by_nid(X509_NAME* p_x509_name, int nid_name);
	int pint(const char** s, int n, int min, int max, int* e);
	time_t ASN1_TIME_get(ASN1_TIME* a,	int *err);
public:
	CMemBlock<char> get_issuer();
	CMemBlock<char> get_subject();
	bool get_beginsystime(struct tm* ptmStart);
	bool get_endsysttime(struct tm* ptmEnd);
	bool get_issign(bool& bSign);
};

#endif

