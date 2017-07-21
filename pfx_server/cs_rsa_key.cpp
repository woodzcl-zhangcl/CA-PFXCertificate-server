/* cs_rsa_key.cpp -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#include "cs_rsa_key.h"

#include <openssl/evp.h>
#include <rsa_locl.h>


cs_rsa_key::cs_rsa_key(void)
{
	m_rsa = 0;
	m_bDel = true;
}

cs_rsa_key::cs_rsa_key(RSA* rsa)
{
	m_rsa = rsa;
	if (!m_rsa)
	{
		m_bDel = true;
	}
	else
	{
		m_bDel = false;
	}
}

cs_rsa_key::~cs_rsa_key(void)
{
	if (m_bDel && m_rsa)
	{
		RSA_free(m_rsa);
		EVP_cleanup();
	}
}

cs_rsa_key::operator bool()const
{
	if (!m_rsa)
	{
		return false;
	}
	else
	{
		return 0<m_n.GetSize()
			&& 0<m_e.GetSize()
			&& 0<m_d.GetSize()
			&& 0<m_p.GetSize()
			&& 0<m_q.GetSize();
	}
}

cs_rsa_key::operator RSA*()const
{
	return m_rsa;
}

bool cs_rsa_key::genKey(int RSAKeyBits, unsigned long e)
{
	BIGNUM* bne = BN_new();
	if (!bne)
	{
		return false;
	}
	int r = BN_set_word(bne, e);
	if (1!=r)
	{
		BN_free(bne);
		return false;
	}
	if (m_rsa)
	{
		if (!m_bDel)
		{
			m_bDel = true;
		}
		else
		{
			RSA_free(m_rsa);
		}
		m_rsa = 0;
	}
	m_rsa = RSA_new();
	if (!m_rsa)
	{
		BN_free(bne);
		return false;
	}
	r = RSA_generate_key_ex(m_rsa, RSAKeyBits, bne, NULL);
	BN_free(bne);
	if (1!=r)
	{
		return false;
	}
	CMemBlock<unsigned char> buf(1024*10);
	int len = 0;
	len = BN_bn2bin(m_rsa->n, buf);
	if (0<len)
	{
		m_n.Resize((size_t)len);
		memcpy(m_n, buf, len);
	}
	len = BN_bn2bin(m_rsa->e, buf);
	if (0<len)
	{
		m_e.Resize((size_t)len);
		memcpy(m_e, buf, len);
	}
	len = BN_bn2bin(m_rsa->d, buf);
	if (0<len)
	{
		m_d.Resize((size_t)len);
		memcpy(m_d, buf, len);
	}
	len = BN_bn2bin(m_rsa->p, buf);
	if (0<len)
	{
		m_p.Resize((size_t)len);
		memcpy(m_p, buf, len);
	}
	len = BN_bn2bin(m_rsa->q, buf);
	if (0<len)
	{
		m_q.Resize((size_t)len);
		memcpy(m_q, buf, len);
	}
	len = BN_bn2bin(m_rsa->dmp1, buf);
	if (0<len)
	{
		m_dmp1.Resize((size_t)len);
		memcpy(m_dmp1, buf, len);
	}
	len = BN_bn2bin(m_rsa->dmq1, buf);
	if (0<len)
	{
		m_dmq1.Resize((size_t)len);
		memcpy(m_dmq1, buf, len);
	}

	len = BN_bn2bin(m_rsa->iqmp, buf);
	if (0<len)
	{
		m_iqmp.Resize((size_t)len);
		memcpy(m_iqmp, buf, len);
	}

	return true;
}

RSA* cs_rsa_key::create(int RSAKeyBits, unsigned long e)
{
	BIGNUM* bne = BN_new();
	if (!bne)
	{
		return 0;
	}
	int r = BN_set_word(bne, e);
	if (1!=r)
	{
		BN_free(bne);
		return 0;
	}
	RSA* rsa = RSA_new();
	if (!rsa)
	{
		BN_free(bne);
		return 0;
	}
	r = RSA_generate_key_ex(rsa, RSAKeyBits, bne, NULL);
	BN_free(bne);
	if (1!=r)
	{
		return 0;
	}

	return rsa;
}

EVP_PKEY* cs_rsa_key::create_evp(int RSAKeyBits, unsigned long e)
{
	BIGNUM* bne = BN_new();
	if (!bne)
	{
		return 0;
	}
	int r = BN_set_word(bne, e);
	if (1!=r)
	{
		BN_free(bne);
		return 0;
	}
	RSA* rsa = RSA_new();
	if (!rsa)
	{
		BN_free(bne);
		return 0;
	}
	r = RSA_generate_key_ex(rsa, RSAKeyBits, bne, NULL);
	BN_free(bne);
	if (1!=r)
	{
		return 0;
	}
	EVP_PKEY* evp_pkey = EVP_PKEY_new();
	if (evp_pkey)
	{
		r = EVP_PKEY_assign_RSA(evp_pkey, rsa);
	}

	return evp_pkey;
}

EVP_PKEY* cs_rsa_key::create_evp(CMemBlock<char> n, CMemBlock<char> e, CMemBlock<char> d, CMemBlock<char> p, CMemBlock<char> q, CMemBlock<char> dmp1, CMemBlock<char> dmq1, CMemBlock<char> iqmp)
{
	EVP_PKEY* evp_pkey = 0;
	RSA* rsa = RSA_new();
	if (rsa)
	{
		if (0<n.GetSize())
		{
			BN_bin2bn((unsigned char*)(char*)n, (int)n.GetSize(), rsa->n); 
		}
		if (0<e.GetSize())
		{
			BN_bin2bn((unsigned char*)(char*)e, (int)e.GetSize(), rsa->e); 
		}
		if (0<d.GetSize())
		{
			BN_bin2bn((unsigned char*)(char*)d, (int)d.GetSize(), rsa->d); 
		}
		if (0<p.GetSize())
		{
			BN_bin2bn((unsigned char*)(char*)p, (int)p.GetSize(), rsa->p); 
		}
		if (0<q.GetSize())
		{
			BN_bin2bn((unsigned char*)(char*)q, (int)q.GetSize(), rsa->q); 
		}
		if (0<dmp1.GetSize())
		{
			BN_bin2bn((unsigned char*)(char*)dmp1, (int)dmp1.GetSize(), rsa->dmp1); 
		}
		if (0<dmq1.GetSize())
		{
			BN_bin2bn((unsigned char*)(char*)dmq1, (int)dmq1.GetSize(), rsa->dmq1); 
		}
		if (0<iqmp.GetSize())
		{
			BN_bin2bn((unsigned char*)(char*)iqmp, (int)iqmp.GetSize(), rsa->iqmp); 
		}
		EVP_PKEY* evp_pkey = EVP_PKEY_new();
		if (evp_pkey)
		{
			int r = EVP_PKEY_assign_RSA(evp_pkey, rsa);
		}
	}

	return evp_pkey;
}

bool cs_rsa_key::setBigNum(CMemBlock<char> n, CMemBlock<char> e, CMemBlock<char> d, CMemBlock<char> p, CMemBlock<char> q, CMemBlock<char> dmp1, CMemBlock<char> dmq1, CMemBlock<char> iqmp)
{
	if (0>=n.GetSize() || 0>=e.GetSize() || 0>=d.GetSize() || 0>=p.GetSize() || 0>=q.GetSize())
	{
		return false;
	}
	if (m_rsa)
	{
		if (!m_bDel)
		{
			m_bDel = true;
		}
		else
		{
			RSA_free(m_rsa);
		}
		m_rsa = 0;
	}
	m_rsa = RSA_new();
	if (!m_rsa)
	{
		return false;
	}
	if (0<n.GetSize())
	{
		m_n.Resize(n.GetSize());
		memcpy(m_n, n, n.GetSize());
		BN_bin2bn((unsigned char*)(char*)n, (int)n.GetSize(), m_rsa->n); 
	}
	if (0<e.GetSize())
	{
		m_e.Resize(e.GetSize());
		memcpy(m_e, e, e.GetSize());
		BN_bin2bn((unsigned char*)(char*)e, (int)e.GetSize(), m_rsa->e); 
	}
	if (0<d.GetSize())
	{
		m_d.Resize(d.GetSize());
		memcpy(m_d, d, d.GetSize());
		BN_bin2bn((unsigned char*)(char*)d, (int)d.GetSize(), m_rsa->d); 
	}
	if (0<p.GetSize())
	{
		m_p.Resize(p.GetSize());
		memcpy(m_p, p, p.GetSize());
		BN_bin2bn((unsigned char*)(char*)p, (int)p.GetSize(), m_rsa->p); 
	}
	if (0<q.GetSize())
	{
		m_q.Resize(q.GetSize());
		memcpy(m_q, q, q.GetSize());
		BN_bin2bn((unsigned char*)(char*)q, (int)q.GetSize(), m_rsa->q); 
	}
	if (0<dmp1.GetSize())
	{
		m_dmp1.Resize(dmp1.GetSize());
		memcpy(m_dmp1, dmp1, dmp1.GetSize());
		BN_bin2bn((unsigned char*)(char*)dmp1, (int)dmp1.GetSize(), m_rsa->dmp1); 
	}
	if (0<dmq1.GetSize())
	{
		m_dmq1.Resize(dmq1.GetSize());
		memcpy(m_dmq1, dmq1, dmq1.GetSize());
		BN_bin2bn((unsigned char*)(char*)dmq1, (int)dmq1.GetSize(), m_rsa->dmq1); 
	}
	if (0<iqmp.GetSize())
	{
		m_iqmp.Resize(iqmp.GetSize());
		memcpy(m_iqmp, iqmp, iqmp.GetSize());
		BN_bin2bn((unsigned char*)(char*)iqmp, (int)iqmp.GetSize(), m_rsa->iqmp); 
	}

	return true;
}

bool cs_rsa_key::getBigNum(CMemBlock<char>& n, CMemBlock<char>& e, CMemBlock<char>& d, CMemBlock<char>& p, CMemBlock<char>& q, CMemBlock<char>& dmp1, CMemBlock<char>& dmq1, CMemBlock<char>& iqmp)const
{
	if (!m_rsa)
	{
		return false;
	}
	if (0<m_n.GetSize())
	{
		n.Resize(m_n.GetSize());
		memcpy(n, m_n, m_n.GetSize());
	}
	if (0<m_e.GetSize())
	{
		e.Resize(m_e.GetSize());
		memcpy(e, m_e, m_e.GetSize());
	}
	if (0<m_d.GetSize())
	{
		d.Resize(m_d.GetSize());
		memcpy(d, m_d, m_d.GetSize());
	}
	if (0<m_p.GetSize())
	{
		p.Resize(m_p.GetSize());
		memcpy(p, m_p, m_p.GetSize());
	}
	if (0<m_q.GetSize())
	{
		q.Resize(m_q.GetSize());
		memcpy(q, m_q, m_q.GetSize());
	}
	if (0<m_dmp1.GetSize())
	{
		dmp1.Resize(m_dmp1.GetSize());
		memcpy(dmp1, m_dmp1, m_dmp1.GetSize());
	}
	if (0<m_dmq1.GetSize())
	{
		dmq1.Resize(m_dmq1.GetSize());
		memcpy(dmq1, m_dmq1, m_dmq1.GetSize());
	}
	if (0<m_iqmp.GetSize())
	{
		iqmp.Resize(m_iqmp.GetSize());
		memcpy(iqmp, m_iqmp, m_iqmp.GetSize());
	}

	return true;
}
