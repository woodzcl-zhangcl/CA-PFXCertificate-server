/* cs_pkcs12.cpp -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#include "cs_pkcs12.h"

#include "cs_x509.h"

#include <openssl/pkcs7.h>


cs_pkcs12::cs_pkcs12(void)
{
	m_p12 = 0;
	m_bDel = true;
}

cs_pkcs12::cs_pkcs12(PKCS12* p12)
{
	m_p12 = p12;
	if (!m_p12)
	{
		m_bDel = true;
	}
	else
	{
		m_bDel = false;
	}
}

cs_pkcs12::~cs_pkcs12(void)
{
	if (m_bDel && m_p12)
	{
		PKCS12_free(m_p12);
		EVP_cleanup();
	}
}

cs_pkcs12::operator bool()const
{
	return m_p12?true:false;
}

cs_pkcs12::operator PKCS12*()const
{
	return m_p12;
}

bool cs_pkcs12::setDerP12(const char* derP12, size_t p12Len)
{
	if (!derP12 || 0>=p12Len)
	{
		return false;
	}
	if (m_p12)
	{
		if (!m_bDel)
		{
			m_bDel = true;
		}
		else
		{
			PKCS12_free(m_p12);
		}
		m_p12 = 0;
	}
	m_p12 = d2i_PKCS12(&m_p12, (const unsigned char**)&derP12, (long)p12Len);
	if (!m_p12)
	{
		return false;
	}

	return true;
}

bool cs_pkcs12::create(const char* pass, EVP_PKEY* prikey, X509* x509, const char* aliasname, bool bSign)
{
	if (!pass || 0>=strlen(pass) || !prikey || !x509)
	{
		return false;
	}
	if (m_p12)
	{
		if (!m_bDel)
		{
			m_bDel = true;
		}
		else
		{
			PKCS12_free(m_p12);
		}
		m_p12 = 0;
	}
	m_p12 = PKCS12_create(const_cast<char*>(pass), aliasname?const_cast<char*>(aliasname):"", prikey, x509, 
		0, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_pbe_WithSHA1And40BitRC2_CBC, PKCS12_DEFAULT_ITER, -1, bSign?KEY_SIG:KEY_EX);
	if (!m_p12)
	{
		return false;
	}

	return true;
}

bool cs_pkcs12::setpass(const char* oldpass, const char* newpass)
{
	if (!oldpass || 0>=strlen(oldpass) || !newpass || 0>=strlen(newpass))
	{
		return false;
	}
	if (!m_p12)
	{
		return false;
	}
	int r = PKCS12_newpass(m_p12, const_cast<char*>(oldpass), const_cast<char*>(newpass));
	if (1!=r)
	{
		return false;
	}

	return true;
}

CMemBlock<char> cs_pkcs12::getDerP12()
{
	CMemBlock<char> c_der_p12;
	if (m_p12)
	{
		int len = i2d_PKCS12(m_p12, 0);
		if (0<len)
		{
			c_der_p12.Resize((size_t)len);
			char* p_c_tmp = c_der_p12;
			len = i2d_PKCS12(m_p12, (unsigned char**)&p_c_tmp);
		}
	}

	return c_der_p12;
}

CMemBlock<char> cs_pkcs12::getX509(const char* pass)
{
	CMemBlock<char> retX509;
	EVP_PKEY* prikey = 0;
	X509* x509 = 0;
	if(1==PKCS12_parse(m_p12, pass, &prikey, &x509, 0))
	{
		if (prikey)
		{
			EVP_PKEY_free(prikey);
		}
		if (x509)
		{
			cs_x509 _x509(x509);
			retX509 = _x509.getDerCert();
			X509_free(x509);
		}
	}

	return retX509;
}
