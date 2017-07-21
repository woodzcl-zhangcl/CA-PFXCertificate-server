/* cs_x509.cpp -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#include "cs_x509.h"

#include "app_util.h"

#include <openssl/x509v3.h>
#include <x509_int.h>


bool fCertSubFitler(const char* p_cert_content, size_t cert_content_len, char* p_nonfilter_cert_content, size_t& len_nonfilter_cert_content)
{
	const unsigned char *pHeader = 0, *pTail = 0;
	pHeader = MemFind((unsigned char*)p_cert_content, cert_content_len, (unsigned char*)"-----BEGIN CERTIFICATE-----", strlen("-----BEGIN CERTIFICATE-----"));
	if (-1!=(size_t)pHeader)
	{
		pTail = MemFind((unsigned char*)p_cert_content, cert_content_len, (unsigned char*)"-----END CERTIFICATE-----", strlen("-----END CERTIFICATE-----"));
		if (-1!=(size_t)pTail)
		{
			size_t count = pTail-pHeader-strlen("-----BEGIN CERTIFICATE-----")-2;
			if (!p_nonfilter_cert_content && 0==len_nonfilter_cert_content)
			{
				len_nonfilter_cert_content = count;
				return true;
			}
			else if(p_nonfilter_cert_content && count<=len_nonfilter_cert_content)
			{
				memcpy(p_nonfilter_cert_content, pHeader+strlen("-----BEGIN CERTIFICATE-----")+1, count);
				len_nonfilter_cert_content = count;
				return true;
			}
		}
	}

	return false;
}

void fCertAddFilter(const char* p_nonfilter_cert_content, size_t len_nonfilter_cert_content, char* p_cert_content, size_t& cert_content_len)
{
	const char Header[] = "-----BEGIN CERTIFICATE-----";
	const char Tail[] = "-----END CERTIFICATE-----";
	size_t len_header = strlen(Header);
	size_t len_tail = strlen(Tail);
	CMemBlock<char> tmp(len_header+1+len_nonfilter_cert_content+len_tail+1);
	memcpy(tmp, Header, len_header);
	memcpy(tmp+len_header, "\n", 1);
	memcpy(tmp+len_header+(size_t)1, p_nonfilter_cert_content, len_nonfilter_cert_content);
	memcpy(tmp+len_header+(size_t)1+len_nonfilter_cert_content, Tail, len_tail);
	memcpy(tmp+len_header+(size_t)1+len_nonfilter_cert_content+len_tail, "\n", 1);
	if (!p_cert_content && 0==cert_content_len)
	{
		cert_content_len = tmp.GetSize();
		return;
	}
	else if (p_cert_content && tmp.GetSize()<=cert_content_len)
	{
		memcpy(p_cert_content, tmp, tmp.GetSize());
		cert_content_len = tmp.GetSize();
		return;
	}
}

cs_x509::cs_x509(void)
{
	m_x509 = 0;
	m_bDel = true;
}

cs_x509::cs_x509(X509* x509)
{
	m_x509 = x509;
	if (!m_x509)
	{
		m_bDel = true;
	}
	else
	{
		m_bDel = false;
	}
}


cs_x509::~cs_x509(void)
{
	if (m_bDel && m_x509)
	{
		X509_free(m_x509);
		EVP_cleanup();
	}
}

cs_x509::operator bool()const
{
	return m_x509?true:false;
}

cs_x509::operator X509*()const
{
	return m_x509;
}

bool cs_x509::setDerCert(const char *derCert, size_t certLen)
{
	if (!derCert || 0>=certLen)
	{
		return false;
	}
	else
	{
		if (m_x509)
		{
			if (!m_bDel)
			{
				m_x509 = 0;
				m_bDel = true;
			}
			else
			{
				X509_free(m_x509);
				m_x509 = 0;
			}
		}
		size_t len = 0;
		bool bDo = fCertSubFitler(derCert, certLen, 0, len);
		if (!bDo)
		{
			return false;
		}
		CMemBlock<char> m_tmp(len);
		bDo = fCertSubFitler(derCert, certLen, m_tmp, len);
		if (!bDo)
		{
			return false;
		}
		CMemBlock<unsigned char> bin_cert = CBase64::Decode((unsigned char*)(char*)m_tmp, (long)m_tmp.GetSize());
		const unsigned char* d = (unsigned char*)bin_cert;
		len = bin_cert.GetSize();
		m_x509 = d2i_X509(&m_x509, &d, (long)len);
		return m_x509?true:false;
	}
}

CMemBlock<char> cs_x509::getDerCert()
{
	CMemBlock<char> x509;
	if (m_x509)
	{
		int len = i2d_X509(m_x509, 0);
		if (0<len)
		{
			x509.Resize((size_t)len);
			char* p_c_tmp = x509;
			len = i2d_X509(m_x509, (unsigned char**)&p_c_tmp);
			CMemBlock<unsigned char> asn_base64_content = CBase64::Encode((unsigned char*)(char*)x509, (long)x509.GetSize());
			size_t len = 0;
			fCertAddFilter((char*)(unsigned char*)asn_base64_content, asn_base64_content.GetSize(), 0, len);
			if (0<len)
			{
				CMemBlock<char> cert_content(len);
				fCertAddFilter((char*)(unsigned char*)asn_base64_content, asn_base64_content.GetSize(), cert_content, len);
				if (0<len)
				{
					x509.Resize(len);
					memcpy(x509, cert_content, len);
				}
			}
		}
	}

	return x509;
}

long cs_x509::get_version()
{
	long l_ver = 0;
	if (m_x509)
	{
		l_ver = X509_get_version(m_x509);
	}

	return l_ver;
}

CMemBlock<char> cs_x509::get_serial()
{
	CMemBlock<char> serial;
	if (m_x509)
	{
		ASN1_INTEGER* asn1_serial = X509_get_serialNumber(m_x509);
		if (asn1_serial)
		{
			if (0<asn1_serial->length)
			{
				serial.Resize(asn1_serial->length);
				memcpy(serial, asn1_serial->data, asn1_serial->length);
			}
			ASN1_INTEGER_free(asn1_serial);
		}
	}

	return serial;
}

CMemBlock<char> cs_x509::get_text_by_nid(X509_NAME* p_x509_name, int nid_name)
{
	CMemBlock<char> text;
	int nNameLen = 512;
	char csCommonName[512] = {0};
	nNameLen = X509_NAME_get_text_by_NID(p_x509_name, nid_name, csCommonName, nNameLen);
	if (-1!=nNameLen)
	{
		text.Resize((size_t)nNameLen+1);
		text[(size_t)nNameLen] = 0;
		memcpy(text, csCommonName, nNameLen);
		if (NID_countryName==nid_name)
		{
			CMemBlock<char> c_tmp(2);
			c_tmp[(size_t)0] = 'C';
			c_tmp[(size_t)1] = '=';
			text = c_tmp+text;
		}
		else if (NID_organizationName==nid_name)
		{
			CMemBlock<char> c_tmp(2);
			c_tmp[(size_t)0] = 'O';
			c_tmp[(size_t)1] = '=';
			text = c_tmp+text;
		}
		else if (NID_organizationalUnitName==nid_name)
		{
			CMemBlock<char> c_tmp(3);
			c_tmp[(size_t)0] = 'O';
			c_tmp[(size_t)1] = 'U';
			c_tmp[(size_t)2] = '=';
			text = c_tmp+text;
		}
		else if (NID_commonName==nid_name)
		{
			CMemBlock<char> c_tmp(3);
			c_tmp[(size_t)0] = 'C';
			c_tmp[(size_t)1] = 'N';
			c_tmp[(size_t)2] = '=';
			text = c_tmp+text;
		}
	}

	return text;
}

CMemBlock<char> cs_x509::get_issuer()
{
	CMemBlock<char> issuer;
	if (m_x509)
	{
		X509_NAME* p_x509_name = X509_get_issuer_name(m_x509);
		if (p_x509_name)
		{
			CMemBlock<char> seperator_Comma(2);
			seperator_Comma[(size_t)0] = ',';
			seperator_Comma[(size_t)1] = ' ';
			CMemBlock<char> dn_C = get_text_by_nid(p_x509_name, NID_countryName);
			CMemBlock<char> dn_O = get_text_by_nid(p_x509_name, NID_organizationName);
			CMemBlock<char> dn_OU = get_text_by_nid(p_x509_name, NID_organizationalUnitName);
			CMemBlock<char> dn_CN = get_text_by_nid(p_x509_name, NID_commonName);
			issuer = dn_C
				+dn_O?seperator_Comma+dn_O:dn_O
				+dn_OU?seperator_Comma+dn_OU:dn_OU
				+dn_CN?seperator_Comma+dn_CN:dn_CN;
			X509_NAME_free(p_x509_name);
		}
	}
	
	return issuer;
}

CMemBlock<char> cs_x509::get_subject()
{
	CMemBlock<char> subject;
	if (m_x509)
	{
		X509_NAME* p_x509_name = X509_get_subject_name(m_x509);
		if (p_x509_name)
		{
			CMemBlock<char> seperator_Comma(2);
			seperator_Comma[(size_t)0] = ',';
			seperator_Comma[(size_t)1] = ' ';
			CMemBlock<char> dn_C = get_text_by_nid(p_x509_name, NID_countryName);
			CMemBlock<char> dn_O = get_text_by_nid(p_x509_name, NID_organizationName);
			CMemBlock<char> dn_OU = get_text_by_nid(p_x509_name, NID_organizationalUnitName);
			CMemBlock<char> dn_CN = get_text_by_nid(p_x509_name, NID_commonName);
			subject = dn_C
				+dn_O?seperator_Comma+dn_O:dn_O
				+dn_OU?seperator_Comma+dn_OU:dn_OU
				+dn_CN?seperator_Comma+dn_CN:dn_CN;
			X509_NAME_free(p_x509_name);
		}
	}
	
	return subject;
}

bool cs_x509::get_beginsystime(struct tm* ptmStart)
{
	if (!m_x509)
	{
		return false;
	}
	int err = 0;
	ASN1_TIME* start = 0;
	time_t ttStart = 0;

	start = X509_get_notBefore(m_x509);
	ttStart = ASN1_TIME_get(start, &err);
	if (0==ttStart)
	{
		return false;
	}
	const tm* _tm = localtime(&ttStart);
	*ptmStart = *_tm;

	return true;
}

bool cs_x509::get_endsysttime(struct tm* ptmEnd)
{
	if (!m_x509)
	{
		return false;
	}
	int err = 0;
	ASN1_TIME* end = 0;
	time_t ttEnd = 0;

	end = X509_get_notAfter(m_x509);
	ttEnd = ASN1_TIME_get(end, &err);
	if (0==ttEnd)
	{
		return false;
	}
	const tm* _tm = localtime(&ttEnd);
	*ptmEnd = *_tm;

	return true;
}

bool cs_x509::get_issign(bool& bSign)
{
	if (!m_x509)
	{
		return false;
	}
	unsigned long lKeyUsage = 0;
	X509_check_ca(m_x509);
	lKeyUsage = m_x509->ex_kusage;
	if ((lKeyUsage&KU_DATA_ENCIPHERMENT)==KU_DATA_ENCIPHERMENT)
	{
		bSign = false;
	}
	else if ((lKeyUsage&KU_DIGITAL_SIGNATURE)==KU_DIGITAL_SIGNATURE)
	{
		bSign = true;
	}
	else
	{
		return false;
	}

	return true;
}

int cs_x509::pint(const char** s, int n, int min, int max, int* e)
{
	int retval = 0;
	while (n) {
		if (**s < '0' || **s > '9') { *e = 1; return 0; }
		retval *= 10;
		retval += **s - '0';
		--n; ++(*s);
	}
	if (retval < min || retval > max) *e = 1;

	return retval;
}

time_t cs_x509::ASN1_TIME_get(ASN1_TIME* a,	int *err)
{
	char days[2][12] =
	{
		{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
		{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
	};
	int dummy;
	const char *s;
	int generalized;
	struct tm t;
	int i, year, isleap, offset;
	time_t retval;
	if (err == NULL) err = &dummy;
	if (a->type == V_ASN1_GENERALIZEDTIME) {
		generalized = 1;
	} else if (a->type == V_ASN1_UTCTIME) {
		generalized = 0;
	} else {
		*err = 1;
		return 0;
	}
	s = (char*)a->data; // Data should be always null terminated
	if (s == NULL || s[a->length] != '\0') {
		*err = 1;
		return 0;
	}
	*err = 0;
	if (generalized) {
		t.tm_year = pint(&s, 4, 0, 9999, err) - 1900;
	} else {
		t.tm_year = pint(&s, 2, 0, 99, err);
		if (t.tm_year < 50) t.tm_year += 100;
	}
	t.tm_mon = pint(&s, 2, 1, 12, err) - 1;
	t.tm_mday = pint(&s, 2, 1, 31, err);
	// NOTE: It's not yet clear, if this implementation is 100% correct
	// for GeneralizedTime... but at least misinterpretation is
	// impossible --- we just throw an exception
	t.tm_hour = pint(&s, 2, 0, 23, err);
	t.tm_min = pint(&s, 2, 0, 59, err);
	if (*s >= '0' && *s <= '9') {
		t.tm_sec = pint(&s, 2, 0, 59, err);
	} else {
		t.tm_sec = 0;
	}
	if (*err) return 0; // Format violation
	if (generalized) {
		// skip fractional seconds if any
		while (*s == '.' || *s == ',' || (*s >= '0' && *s <= '9')) ++s;
		// special treatment for local time
		if (*s == 0) {
			t.tm_isdst = -1;
			retval = mktime(&t); // Local time is easy :)
			if (retval == (time_t)-1) {
				*err = 2;
				retval = 0;
			}
			return retval;
		}
	}
	if (*s == 'Z') {
		offset = 0;
		++s;
	} else if (*s == '-' || *s == '+') {
		i = (*s++ == '-');
		offset = pint(&s, 2, 0, 12, err);
		offset *= 60;
		offset += pint(&s, 2, 0, 59, err);
		if (*err) return 0; // Format violation
		if (i) offset = -offset;
	} else {
		*err = 1;
		return 0;
	}
	if (*s) {
		*err = 1;
		return 0;
	}
	// And here comes the hard part --- there's no standard function to
	// convert struct tm containing UTC time into time_t without
	// messing global timezone settings (breaks multithreading and may
	// cause other problems) and thus we have to do this "by hand"
	//
	// NOTE: Overflow check does not detect too big overflows, but is
	// sufficient thanks to the fact that year numbers are limited to four
	// digit non-negative values.
	retval = t.tm_sec;
	retval += (t.tm_min - offset) * 60;
	retval += t.tm_hour * 3600;
	retval += (t.tm_mday - 1) * 86400;
	year = t.tm_year + 1900;
	if ( sizeof (time_t) == 4) {
		// This is just to avoid too big overflows being undetected, finer
		// overflow detection is done below.
		if (year < 1900 || year > 2040) *err = 2;
	}
	// FIXME: Does POSIX really say, that all years divisible by 4 are
	// leap years (for consistency)??? Fortunately, this problem does
	// not exist for 32-bit time_t and we should'nt be worried about
	// this until the year of 2100 :)
	isleap = ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
	for (i = t.tm_mon - 1; i >= 0; --i) retval += days[isleap][i] * 86400;
	retval += (year - 1970) * 31536000;
	if (year < 1970) {
		retval -= ((1970 - year + 2) / 4) * 86400;
		if ( sizeof (time_t) > 4) {
			for (i = 1900; i >= year; i -= 100) {
				if (i % 400 == 0) continue ;
				retval += 86400;
			}
		}
		if (retval >= 0) *err = 2;
	} else {
		retval += ((year - 1970 + 1) / 4) * 86400;
		if ( sizeof (time_t) > 4) {
			for (i = 2100; i < year; i += 100) {
				// The following condition is the reason to
				// start with 2100 instead of 2000
				if (i % 400 == 0) continue ;
				retval -= 86400;
			}
		}
		if (retval < 0) *err = 2;
	}
	if (*err) retval = 0;

	return retval;

}
