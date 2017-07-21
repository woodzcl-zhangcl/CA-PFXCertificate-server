/* CPFXServer.cpp -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#include "CPFXServer.h"

#include "cs_openssl_init.h"
#include "cs_rsa_key.h"
#include "cs_x509.h"
#include "cs_pkcs12.h"
#include "cs_rsa_digest.h"
#include "cs_rsa_crypt.h"


// time as second
#define TT_SPAN 60

CPFXServer::CPFXServer(bool bSSL, const char* port, const char* certfile_pem_name, const char* prikeyfile_pem_name, const char* password):
CHttpServer(bSSL, port, certfile_pem_name, prikeyfile_pem_name, password)
{
	CBase64::setDelimiterSet(0);
}

CPFXServer::~CPFXServer()
{

}

CMemBlock<char> CPFXServer::provide_server(CMemBlock<char> bodyData, CMemBlock<char> url, CMemBlock<char> cookie, CMemBlock<char>& content_type, CMemBlock<char>& des, bool& bOK, int& RETCode)
{
	CMemBlock<char> response_body;

	const char* p_c_command_p10 = "request_p10";
	const char* p_c_command_signcert_pfx = "request_signcert_pfx";
	const char* p_c_command_signcert_enccert_pfx = "request_signcert_enccert_pfx";
	if (url.GetSize()==strlen(p_c_command_p10) && 0==memcmp(url, p_c_command_p10, url.GetSize()))
	{
		response_body = get_rsa_p10_encpubkey(bodyData, cookie, content_type, des, bOK, RETCode);
	}
	else if(url.GetSize()==strlen(p_c_command_signcert_pfx) && 0==memcmp(url, p_c_command_signcert_pfx, url.GetSize()))
	{
		response_body = get_rsa_signcert_pfx(bodyData, cookie, content_type, des, bOK, RETCode);
	}
	else if (url.GetSize()==strlen(p_c_command_signcert_enccert_pfx) && 0==memcmp(url, p_c_command_signcert_enccert_pfx, url.GetSize()))
	{
		response_body = get_rsa_signcert_enccert_pfx(bodyData, cookie, content_type, des, bOK, RETCode);
	}
	else
	{
		bOK = false;
		RETCode = 404;
		const char* p_c_not_found = "Not Found";
		size_t des_len = strlen(p_c_not_found);
		des.Resize(des_len);
		memcpy(des, p_c_not_found, des_len);
	}
	autoRemoveSession();

	return response_body;
}

bool CPFXServer::findSession(CMemBlock<char> ID, PFXSession& session)
{
	std::vector<PFXSession>::iterator it = m_session.begin();
	for(;it!=m_session.end();)
	{
		PFXSession& _session = (*it);
		if (0!=memcmp(_session.id, ID, _session.id.GetSize()))
		{
			it++;
		}
		else
		{
			session.id.Resize(_session.id.GetSize());
			memcpy(session.id, _session.id, _session.id.GetSize());
			session.tt_create = _session.tt_create;
			session.n.Resize(_session.n.GetSize());
			memcpy(session.n, _session.n, _session.n.GetSize());
			session.e.Resize(_session.e.GetSize());
			memcpy(session.e, _session.e, _session.e.GetSize());
			session.d.Resize(_session.d.GetSize());
			memcpy(session.d, _session.d, _session.d.GetSize());
			session.p.Resize(_session.p.GetSize());
			memcpy(session.p, _session.p, _session.p.GetSize());
			session.q.Resize(_session.q.GetSize());
			memcpy(session.q, _session.q, _session.q.GetSize());
			session.dmp1.Resize(_session.dmp1.GetSize());
			memcpy(session.dmp1, _session.dmp1, _session.dmp1.GetSize());
			session.dmq1.Resize(_session.dmq1.GetSize());
			memcpy(session.dmq1, _session.dmq1, _session.dmq1.GetSize());
			session.iqmp.Resize(_session.iqmp.GetSize());
			memcpy(session.iqmp, _session.iqmp, _session.iqmp.GetSize());
			return true;
		}
	}

	return false;
}

void CPFXServer::insertSession(PFXSession& session)
{
	PFXSession _session;
	_session.id.Resize(session.id.GetSize());
	memcpy(_session.id, session.id, session.id.GetSize());
	_session.tt_create = session.tt_create;
	_session.n.Resize(session.n.GetSize());
	memcpy(_session.n, session.n, session.n.GetSize());
	_session.e.Resize(session.e.GetSize());
	memcpy(_session.e, session.e, session.e.GetSize());
	_session.d.Resize(session.d.GetSize());
	memcpy(_session.d, session.d, session.d.GetSize());
	_session.p.Resize(session.p.GetSize());
	memcpy(_session.p, session.p, session.p.GetSize());
	_session.q.Resize(session.q.GetSize());
	memcpy(_session.q, session.q, session.q.GetSize());
	_session.dmp1.Resize(session.dmp1.GetSize());
	memcpy(_session.dmp1, session.dmp1, session.dmp1.GetSize());
	_session.dmq1.Resize(session.dmq1.GetSize());
	memcpy(_session.dmq1, session.dmq1, session.dmq1.GetSize());
	_session.iqmp.Resize(session.iqmp.GetSize());
	memcpy(_session.iqmp, session.iqmp, session.iqmp.GetSize());
	m_session.push_back(_session);
}

void CPFXServer::deleteSession(CMemBlock<char> ID)
{
	std::vector<PFXSession>::iterator it = m_session.begin();
	for(;it!=m_session.end();)
	{
		PFXSession& _session = (*it);
		if (0==memcmp(_session.id, ID, _session.id.GetSize()))
		{
			m_session.erase(it);
			return;
		}
	}
}

bool CPFXServer::isSessionAvailable(CMemBlock<char> ID)
{
	std::vector<PFXSession>::iterator it = m_session.begin();
	for(;it!=m_session.end();)
	{
		PFXSession& _session = (*it);
		if (0==memcmp(_session.id, ID, _session.id.GetSize()))
		{
			time_t _tt;
			time(&_tt);
			long long tt_span = _tt-_session.tt_create;
			return tt_span<TT_SPAN?true:false;
		}
	}

	return false;
}

void CPFXServer::autoRemoveSession()
{
	time_t _tt;
	time(&_tt);
	std::vector<PFXSession>::iterator it = m_session.begin();
	for(;it!=m_session.end();)
	{
		PFXSession& _session = (*it);
		long long tt_span = _tt-_session.tt_create;
		if (tt_span>=(long long)TT_SPAN)
		{
			it = m_session.erase(it);
		}
		else
		{
			it++;
		}
	}
}

CMemBlock<unsigned char> CPFXServer::get_encode_oid(const long* l_oid, size_t s_t_len)
{
	CMemBlock<unsigned char> ret;
	CMemBlock<char> m_tmp;
	const long* p_long = l_oid;
	size_t len = s_t_len;
	if (OIDEncode(p_long, len, NULL))
	{	
		m_tmp.Resize(len);
		len = s_t_len;
		if (OIDEncode(p_long, len, m_tmp))
		{
			ret.Resize(m_tmp.GetSize());
			memcpy(ret, m_tmp, len);
		}
	}

	return ret;
}

CMemBlock<unsigned char> CPFXServer::get_encode_oid(const char* s_oid)
{
	CMemBlock<unsigned char> ret;
	if (s_oid && 0<strlen(s_oid))
	{
		std::vector<std::string> std_vec_str;
		const char *p_s_t_begin = s_oid, *p_s_t_end = 0;
		size_t count = 0;
		while(1)
		{
			p_s_t_end = strchr(p_s_t_begin, '.');
			if (0==p_s_t_end)
			{
				count = strlen(s_oid)-(p_s_t_begin-s_oid);
				CMemBlock<char> m_tmp(count+1);
				m_tmp[count] = 0;
				memcpy(m_tmp, p_s_t_begin, count);
				std_vec_str.push_back((char*)m_tmp);
				break;
			}
			else
			{
				count = p_s_t_end-p_s_t_begin;
				CMemBlock<char> m_tmp(count+1);
				m_tmp[count] = 0;
				memcpy(m_tmp, p_s_t_begin, count);
				std_vec_str.push_back((char*)m_tmp);
				p_s_t_begin = p_s_t_end+1;
			}
		}
		size_t len = std_vec_str.size();
		CMemBlock<long> m_l_oid(len);
		for(size_t s_t=0; s_t<len; s_t++)
		{
			m_l_oid[s_t] = atol(std_vec_str[s_t].c_str());
		}
		ret = get_encode_oid((long*)m_l_oid, len);
	}

	return ret;
}

CMemBlock<char> CPFXServer::gen_rsa_p10(void* p_rsa_key, const char* p_c_digest_alg_oid)
{
	CMemBlock<char> p10;
	if (p_rsa_key && p_c_digest_alg_oid)
	{
		cs_rsa_key& rsa_key = *(cs_rsa_key*)p_rsa_key;
		CMemBlock<unsigned char> mem_empty;
		const char* p_c_default = "default";
		CMemBlock<unsigned char> mem_default;
		mem_default.SetMemFixed((unsigned char*)p_c_default, strlen(p_c_default));
		CMemBlock<unsigned char> mem_zero(1);
		mem_zero[0] = 0;
		CMemBlock<unsigned char> asn_null(2);
		asn_null[0] = 0x05;
		asn_null[1] = 0x00;
		size_t len = 0;
		CMemBlock<char> p_tmp;
		CMemBlock<unsigned char> p_utmp;

		CMemBlock<unsigned char> asn_ver = CTLVOf1Level::Encode((unsigned char)0x02, mem_zero.GetSize(), mem_zero);
		CMemBlock<unsigned char> asn_dn = CTLVOf1Level::Encode((unsigned char)0x30, mem_empty.GetSize(), mem_empty);

		CMemBlock<unsigned char> en_oid_rsaencryption = get_encode_oid("1.2.840.113549.1.1.1");
		CMemBlock<unsigned char> asn_oid_rsaencryption = CTLVOf1Level::Encode((unsigned char)0x06, en_oid_rsaencryption.GetSize(), en_oid_rsaencryption);
		p_utmp = asn_oid_rsaencryption+asn_null;
		CMemBlock<unsigned char> asn_alg_pubkey = CTLVOf1Level::Encode((unsigned char)0x30, p_utmp.GetSize(), p_utmp);
		p_tmp = get_rsa_encpubkey(p_rsa_key);
		p_utmp.Resize(p_tmp.GetSize());
		memcpy(p_utmp, p_tmp, p_tmp.GetSize());
		CMemBlock<unsigned char> asn_seq_II = CBase64::Decode(p_utmp, (long)p_utmp.GetSize());
		p_utmp.Resize(asn_seq_II.GetSize()+1);
		p_utmp[0] = 0;;
		memcpy(p_utmp+(size_t)1, asn_seq_II, asn_seq_II.GetSize());
		CMemBlock<unsigned char> asn_bit_seq_II = CTLVOf1Level::Encode((unsigned char)0x03, p_utmp.GetSize(), p_utmp);
		p_utmp = asn_alg_pubkey+asn_bit_seq_II;
		CMemBlock<unsigned char> asn_pubkey = CTLVOf1Level::Encode((unsigned char)0x30, p_utmp.GetSize(), p_utmp);

		CMemBlock<unsigned char> en_oid_email = get_encode_oid("1.2.840.113549.1.9.1");
		CMemBlock<unsigned char> asn_oid_email = CTLVOf1Level::Encode((unsigned char)0x06, en_oid_email.GetSize(), en_oid_email);
		CMemBlock<unsigned char> asn_org = CTLVOf1Level::Encode((unsigned char)0x16, mem_empty.GetSize(), mem_empty);
		CMemBlock<unsigned char> asn_set_org = CTLVOf1Level::Encode((unsigned char)0x31, asn_org.GetSize(), asn_org);
		p_utmp = asn_oid_email+asn_set_org;
		CMemBlock<unsigned char> asn_seq_info = CTLVOf1Level::Encode((unsigned char)0x30, p_utmp.GetSize(), p_utmp);
		CMemBlock<unsigned char> asn_context0_info = CTLVOf1Level::Encode((unsigned char)0xA0, asn_seq_info.GetSize(), asn_seq_info);

		p_utmp = asn_ver+asn_dn+asn_pubkey+asn_context0_info;
		CMemBlock<unsigned char> asn_part1 = CTLVOf1Level::Encode((unsigned char)0x30, p_utmp.GetSize(), p_utmp);

		cs_rsa_digest rsa_digest;
		cs_rsa_crypt rsa_crypt;
		CMemBlock<char> c_signed;
		CMemBlock<char> c_digest;
		CMemBlock<unsigned char> encode_digest_oid;
		CMemBlock<unsigned char> asn_digest_oid;
		CMemBlock<unsigned char> asn_part2;
		CMemBlock<unsigned char> asn_part3;

		if (rsa_digest.init(p_c_digest_alg_oid))
		{
			if (rsa_digest.update((char*)(unsigned char*)asn_part1, asn_part1.GetSize()))
			{
				if (rsa_digest.final())
				{
					c_digest.Resize(rsa_digest.ui_digest_len);
					memcpy(c_digest, rsa_digest.uc_digest, c_digest.GetSize());
					size_t len = rsa_crypt.getLengthOfBytes(rsa_key);
					c_signed.Resize(len);
					if (rsa_crypt.private_encrypt(rsa_key, c_digest.GetSize(), c_digest, c_signed))
					{
						p_utmp.Resize(c_signed.GetSize()+1);
						p_utmp[0] = 0;
						memcpy(p_utmp+(size_t)1, c_signed, c_signed .GetSize());
						asn_part3 = CTLVOf1Level::Encode((unsigned char)0x03, p_utmp.GetSize(), p_utmp);
						if (0==memcmp((const void*)"md4", (const void*)p_c_digest_alg_oid, (size_t)3))
						{
							encode_digest_oid = get_encode_oid("1.2.840.113549.1.1.3");
						}
						else if (0==memcmp((const void*)"md5", (const void*)p_c_digest_alg_oid, (size_t)3))
						{
							encode_digest_oid = get_encode_oid("1.2.840.113549.1.1.4");
						}
						else if (0==memcmp((const void*)"sha1", (const void*)p_c_digest_alg_oid, (size_t)4))
						{
							encode_digest_oid = get_encode_oid("1.2.840.113549.1.1.5");
						}
						else if (0==memcmp((const void*)"sha256", (const void*)p_c_digest_alg_oid, (size_t)6))
						{
							encode_digest_oid = get_encode_oid("1.2.840.113549.1.1.11");
						}
						else if (0==memcmp((const void*)"sha384", (const void*)p_c_digest_alg_oid, (size_t)6))
						{
							encode_digest_oid = get_encode_oid("1.2.840.113549.1.1.12");
						}
						else if (0==memcmp((const void*)"sha512", (const void*)p_c_digest_alg_oid, (size_t)6))
						{
							encode_digest_oid = get_encode_oid("1.2.840.113549.1.1.13");
						}
						asn_digest_oid = CTLVOf1Level::Encode((unsigned char)0x06, encode_digest_oid.GetSize(), encode_digest_oid);
						p_utmp = asn_digest_oid+asn_null;
						asn_part2 = CTLVOf1Level::Encode((unsigned char)0x30, p_utmp.GetSize(), p_utmp);
						p_utmp = asn_part1+asn_part2+asn_part3;
						CMemBlock<unsigned char> m_p10 = CTLVOf1Level::Encode((unsigned char)0x30, p_utmp.GetSize(), p_utmp);
						CMemBlock<unsigned char> m_p10_base64 = CBase64::Encode(m_p10, (long)m_p10.GetSize());
						p10.Resize(m_p10_base64.GetSize());
						memcpy(p10, m_p10_base64, m_p10_base64.GetSize());
					}
				}
			}
		}
	}

	return p10;
}

CMemBlock<char> CPFXServer::get_rsa_encpubkey(void* p_rsa_key)
{
	CMemBlock<char> encpubkey;
	if (p_rsa_key)
	{
		cs_rsa_key& rsa_key = *(cs_rsa_key*)p_rsa_key;
		CMemBlock<char>n, e, d, p, q, dmp1, dmq1, iqmp;
		rsa_key.getBigNum(n, e, d, p, q, dmp1, dmq1, iqmp);
		CMemBlock<unsigned char> _n(n.GetSize()+1), _e(e.GetSize());
		_n[0] = 0;
		memcpy(_n+(size_t)1, n, n.GetSize());
		memcpy(_e, e, e.GetSize());
		CMemBlock<unsigned char> asn_n = CTLVOf1Level::Encode((unsigned char)0x02, _n.GetSize(), _n);
		CMemBlock<unsigned char> asn_e = CTLVOf1Level::Encode((unsigned char)0x02, _e.GetSize(), _e);
		CMemBlock<unsigned char> m_utmp = asn_n+asn_e;
		CMemBlock<unsigned char> asn_seq_II = CTLVOf1Level::Encode((unsigned char)0x30, m_utmp.GetSize(), m_utmp);
		m_utmp = CBase64::Encode(asn_seq_II, (long)asn_seq_II.GetSize());
		encpubkey.Resize(m_utmp.GetSize());
		memcpy(encpubkey, m_utmp, m_utmp.GetSize());
	}

	return encpubkey;
}

CMemBlock<char> CPFXServer::get_rsa_p10_encpubkey(CMemBlock<char> bodyData, CMemBlock<char> cookie, CMemBlock<char>& content_type, CMemBlock<char>& des, bool& bOK, int& RETCode)
{
	//p10=p10&encpubkey=encpubkey
	bOK = false;
	CMemBlock<char> body;
	const char* p_c_ct = "text/plain;charset=utf-8";
	content_type.Resize(strlen(p_c_ct));
	memcpy(content_type, p_c_ct, content_type.GetSize());
	PFXSession find_session;
	if (findSession(cookie, find_session))
	{
		deleteSession(cookie);
	}
	std::map<std::string, std::string> KV;
	splitForm(bodyData, KV);
	const std::string ss_c_keybits = "keybits";
	const std::string ss_c_alg_digest_oid = "digest_c_alg_oid";
	std::map<std::string, std::string>::iterator it_keybits = KV.find(ss_c_keybits);
	std::map<std::string, std::string>::iterator it_alg_digest_oid = KV.find(ss_c_alg_digest_oid);
	if (it_keybits==KV.end() || it_alg_digest_oid==KV.end()
		|| ""==KV[ss_c_keybits] || ""==KV[ss_c_alg_digest_oid])
	{
		bOK = false;
		RETCode = 406;
		const char* p_c_not_accept = "Not Accept";
		des.Resize(strlen(p_c_not_accept));
		memcpy(des, p_c_not_accept, des.GetSize());
	}
	else
	{
		if ("1024"!=KV[ss_c_keybits]
			&& "2048"!=KV[ss_c_keybits]
			&& "4096"!=KV[ss_c_keybits]
			&& "md4"!=KV[ss_c_alg_digest_oid]
			&& "md5"!=KV[ss_c_alg_digest_oid]
			&& "sha1"!=KV[ss_c_alg_digest_oid]
			&& "sha256"!=KV[ss_c_alg_digest_oid]
			&& "sha384"!=KV[ss_c_alg_digest_oid]
			&& "sha512"!=KV[ss_c_alg_digest_oid])
		{
			bOK = false;
			RETCode = 406;
			const char* p_c_not_accept = "Not Accept";
			des.Resize(strlen(p_c_not_accept));
			memcpy(des, p_c_not_accept, des.GetSize());
		}
		else
		{
			int keybits = atoi(KV[ss_c_keybits].c_str());
			const char* p_c_digest_alg_oid = KV[ss_c_alg_digest_oid].c_str();
			cs_rsa_key rsa_key;
			if (!rsa_key.genKey(keybits))
			{
				bOK = false;
				RETCode = 500;
				const char* p_c_not_complete = "Not Complete";
				des.Resize(strlen(p_c_not_complete));
				memcpy(des, p_c_not_complete, des.GetSize());
			}
			else
			{
				CMemBlock<char> p10 = gen_rsa_p10(&rsa_key, p_c_digest_alg_oid);
				if (0>=p10.GetSize())
				{
					bOK = false;
					RETCode = 500;
					const char* p_c_not_complete = "Not Complete";
					des.Resize(strlen(p_c_not_complete));
					memcpy(des, p_c_not_complete, des.GetSize());
				}
				else
				{
					PFXSession new_session;
					time(&new_session.tt_create);
					new_session.id.Resize(cookie.GetSize());
					memcpy(new_session.id, cookie, cookie.GetSize());
					rsa_key.getBigNum(
						new_session.n, 
						new_session.e,
						new_session.d,
						new_session.p,
						new_session.q,
						new_session.dmp1,
						new_session.dmq1,
						new_session.iqmp);
					insertSession(new_session);
					const char* p_c_p10 = "p10=";
					CMemBlock<char> m_p10;
					m_p10.SetMemFixed(p_c_p10, strlen(p_c_p10));
					body = m_p10+p10;
					CMemBlock<char> m_encpubkey = get_rsa_encpubkey(&rsa_key);
					const char* p_c_encpubkey = "&encpubkey=";
					CMemBlock<char> m_tmp_encpubkey;
					m_tmp_encpubkey.SetMemFixed(p_c_encpubkey, strlen(p_c_encpubkey));
					body = body+m_tmp_encpubkey+m_encpubkey;
					bOK = true;
				}
			}
		}
	}

	return body;
}

CMemBlock<char> CPFXServer::get_rsa_signcert_pfx(CMemBlock<char> bodyData, CMemBlock<char> cookie, CMemBlock<char>& content_type, CMemBlock<char>& des, bool& bOK, int& RETCode)
{
	CMemBlock<char> signcert_pfx;
	bOK = false;
	CMemBlock<char> body;
	const char* p_c_ct = "text/plain;charset=utf-8";
	content_type.Resize(strlen(p_c_ct));
	memcpy(content_type, p_c_ct, content_type.GetSize());
	PFXSession find_session;
	if (!findSession(cookie, find_session))
	{
		bOK = false;
		RETCode = 410;
		const char* p_c_deleted = "Deleted";
		des.Resize(strlen(p_c_deleted));
		memcpy(des, p_c_deleted, des.GetSize()); 
	}
	else
	{
		std::map<std::string, std::string> KV;
		splitForm(bodyData, KV);
		const std::string ss_c_signcert = "Signcert";
		const std::string ss_c_password = "Password";
		std::map<std::string, std::string>::iterator it_signcert = KV.find(ss_c_signcert);
		std::map<std::string, std::string>::iterator it_password = KV.find(ss_c_password);
		if (it_signcert==KV.end() || it_password==KV.end()
		 	|| ""==KV[ss_c_signcert] || ""==KV[ss_c_password])
		{
			bOK = false;
			RETCode = 406;
			const char* p_c_not_accept = "Not Accept";
			des.Resize(strlen(p_c_not_accept));
			memcpy(des, p_c_not_accept, des.GetSize());
		}
		else
		{
			cs_rsa_key rsa_key;
			EVP_PKEY* prikey = rsa_key.create_evp(find_session.n, find_session.e, find_session.d, find_session.p, find_session.q, find_session.dmp1, find_session.dmq1, find_session.iqmp);
			deleteSession(cookie);
			if (!prikey)
			{
				bOK = false;
				RETCode = 500;
				const char* p_c_not_complete = "Not Complete";
				des.Resize(strlen(p_c_not_complete));
				memcpy(des, p_c_not_complete, des.GetSize());
			}
			else
			{
				CMemBlock<unsigned char> u_x509 = CBase64::Decode((unsigned char*)KV[ss_c_signcert].c_str(), (long)strlen(KV[ss_c_signcert].c_str()));
				CMemBlock<char> c_x509;
				c_x509.SetMemFixed((char*)(unsigned char*)u_x509, u_x509.GetSize());
				cs_x509 x509;
				x509.setDerCert(c_x509, c_x509.GetSize());
				cs_pkcs12 _pkcs12;
				if (!_pkcs12.create(KV[ss_c_password].c_str(), prikey, x509, 0, true))
				{
					EVP_PKEY_free(prikey);
					bOK = false;
					RETCode = 500;
					const char* p_c_not_complete = "Not Complete";
					des.Resize(strlen(p_c_not_complete));
					memcpy(des, p_c_not_complete, des.GetSize());
				}
				else
				{
					EVP_PKEY_free(prikey);
					CMemBlock<char> m_p12 = _pkcs12.getDerP12();
					CMemBlock<unsigned char> m_base64_p12 = CBase64::Encode((unsigned char*)(char*)m_p12, (long)m_p12.GetSize());
					CMemBlock<char> m_s_base64_p12(m_base64_p12.GetSize()+1);
					m_s_base64_p12[m_base64_p12.GetSize()] = 0;
					memcpy(m_s_base64_p12, m_base64_p12, m_base64_p12.GetSize());
					const char* pk = "Signcert_pfx";
					const char* pv = m_s_base64_p12;
					const char  *_k[] = {pk}, *_v[] = {pv};
					std::string ss_form = genForm(_k, 1, _v, 1);
					signcert_pfx.Resize(strlen(ss_form.c_str()));
					memcpy(signcert_pfx, ss_form.c_str(), signcert_pfx.GetSize());
					bOK = true;
				}
			}
		}
	}
	

	return signcert_pfx;
}

CMemBlock<char> CPFXServer::get_rsa_signcert_enccert_pfx(CMemBlock<char> bodyData, CMemBlock<char> cookie, CMemBlock<char>& content_type, CMemBlock<char>& des, bool& bOK, int& RETCode)
{
	CMemBlock<char> signcert_pfx;
	CMemBlock<char> enccert_pfx;
	CMemBlock<char> signcert_enccert_pfx;
	bOK = false;
	CMemBlock<char> body;
	const char* p_c_ct = "text/plain;charset=utf-8";
	content_type.Resize(strlen(p_c_ct));
	memcpy(content_type, p_c_ct, content_type.GetSize());
	PFXSession find_session;
	if (!findSession(cookie, find_session))
	{
		bOK = false;
		RETCode = 410;
		const char* p_c_deleted = "Deleted";
		des.Resize(strlen(p_c_deleted));
		memcpy(des, p_c_deleted, des.GetSize()); 
	}
	else
	{
		std::map<std::string, std::string> KV;
		splitForm(bodyData, KV);
		const std::string ss_c_signcert = "Signcert";
		const std::string ss_c_enccert = "Enccert";
		const std::string ss_c_encprikey = "Encprikey";
		const std::string ss_c_encsymmetry = "Encsymmetry";
		const std::string ss_c_password = "Password";
		std::map<std::string, std::string>::iterator it_signcert = KV.find(ss_c_signcert);
		std::map<std::string, std::string>::iterator it_enccert = KV.find(ss_c_enccert);
		std::map<std::string, std::string>::iterator it_encprikey = KV.find(ss_c_encprikey);
		std::map<std::string, std::string>::iterator it_encsymmetry = KV.find(ss_c_encsymmetry);
		std::map<std::string, std::string>::iterator it_password = KV.find(ss_c_password);
		if (it_signcert==KV.end() 
			|| it_enccert==KV.end()
			|| it_encprikey==KV.end()
			|| it_encsymmetry==KV.end()
			|| it_password==KV.end()
		 	|| ""==KV[ss_c_signcert] 
		 	|| ""==KV[ss_c_enccert]
		 	|| ""==KV[ss_c_encprikey]
		 	|| ""==KV[ss_c_encsymmetry]
		 	|| ""==KV[ss_c_password])
		{
			bOK = false;
			RETCode = 406;
			const char* p_c_not_accept = "Not Accept";
			des.Resize(strlen(p_c_not_accept));
			memcpy(des, p_c_not_accept, des.GetSize());
		}
		else
		{
			cs_rsa_key rsa_key;
			rsa_key.setBigNum(find_session.n, find_session.e, find_session.d, find_session.p, find_session.q, find_session.dmp1, find_session.dmq1, find_session.iqmp);
			EVP_PKEY* prikey = rsa_key.create_evp(find_session.n, find_session.e, find_session.d, find_session.p, find_session.q, find_session.dmp1, find_session.dmq1, find_session.iqmp);
			deleteSession(cookie);
			if (!prikey)
			{
				bOK = false;
				RETCode = 500;
				const char* p_c_not_complete = "Not Complete";
				des.Resize(strlen(p_c_not_complete));
				memcpy(des, p_c_not_complete, des.GetSize());
			}
			else
			{
				CMemBlock<unsigned char> u_x509 = CBase64::Decode((unsigned char*)KV[ss_c_signcert].c_str(), (long)strlen(KV[ss_c_signcert].c_str()));
				CMemBlock<char> c_x509;
				c_x509.SetMemFixed((char*)(unsigned char*)u_x509, u_x509.GetSize());
				cs_x509 x509;
				x509.setDerCert(c_x509, c_x509.GetSize());
				cs_pkcs12 _pkcs12;
				if (!_pkcs12.create(KV[ss_c_password].c_str(), prikey, x509, 0, true))
				{
					EVP_PKEY_free(prikey);
					bOK = false;
					RETCode = 500;
					const char* p_c_not_complete = "Not Complete";
					des.Resize(strlen(p_c_not_complete));
					memcpy(des, p_c_not_complete, des.GetSize());
				}
				else
				{
					EVP_PKEY_free(prikey);
					CMemBlock<char> m_p12 = _pkcs12.getDerP12();
					CMemBlock<unsigned char> m_base64_signcert_p12 = CBase64::Encode((unsigned char*)(char*)m_p12, (long)m_p12.GetSize());
					CMemBlock<char> m_s_signcert_pfx(m_base64_signcert_p12.GetSize()+1);
					m_s_signcert_pfx[m_base64_signcert_p12.GetSize()] = 0;
					memcpy(m_s_signcert_pfx, m_base64_signcert_p12, m_base64_signcert_p12.GetSize());
					// 
					cs_rsa_crypt rsa_crypt;
					int len = rsa_crypt.getLengthOfBytes(rsa_key);
					CMemBlock<char> m_rc4_password(len);
					len = rsa_crypt.private_decrypt(rsa_key, (size_t)len, KV[ss_c_encsymmetry].c_str(), m_rc4_password);
					if (-1==len)
					{
						bOK = false;
						RETCode = 500;
						const char* p_c_not_complete = "Not Complete";
						des.Resize(strlen(p_c_not_complete));
						memcpy(des, p_c_not_complete, des.GetSize());
					}
					else
					{
						m_rc4_password.Resize((size_t)len);
						CMemBlock<char> m_encprikey(strlen(KV[ss_c_encprikey].c_str()));
						if (!rsa_crypt.rc4_decrypt(KV[ss_c_encprikey].c_str(), strlen(KV[ss_c_encprikey].c_str()), m_rc4_password, m_rc4_password.GetSize(), m_encprikey))
						{
							bOK = false;
							RETCode = 500;
							const char* p_c_not_complete = "Not Complete";
							des.Resize(strlen(p_c_not_complete));
							memcpy(des, p_c_not_complete, des.GetSize());
						}
						else
						{
							std::vector<TLVNode> nodelist0;
							if (!CTLVOf1Level::Decode((unsigned char*)(char*)m_encprikey, m_encprikey.GetSize(), nodelist0))
							{
								bOK = false;
								RETCode = 500;
								const char* p_c_not_complete = "Not Complete";
								des.Resize(strlen(p_c_not_complete));
								memcpy(des, p_c_not_complete, des.GetSize());
							}
							else if(1==nodelist0.size() && 0x30==nodelist0[0].T)
							{
								std::vector<TLVNode> nodelist1;
								if (!CTLVOf1Level::Decode(nodelist0[0].V, nodelist0[0].L, nodelist1))
								{
									bOK = false;
									RETCode = 500;
									const char* p_c_not_complete = "Not Complete";
									des.Resize(strlen(p_c_not_complete));
									memcpy(des, p_c_not_complete, des.GetSize());
								}
								else if(9==nodelist1.size()
									&& 0x02==nodelist1[1].T
									&& 0x02==nodelist1[2].T
									&& 0x02==nodelist1[3].T
									&& 0x02==nodelist1[4].T
									&& 0x02==nodelist1[5].T
									&& 0x02==nodelist1[6].T
									&& 0x02==nodelist1[7].T
									&& 0x02==nodelist1[8].T)
								{
									CMemBlock<char> n, e, d, p, q, dmp1, dmq1, iqmp;
									n.SetMemFixed((char*)(unsigned char*)nodelist1[1].V, nodelist1[1].L);
									e.SetMemFixed((char*)(unsigned char*)nodelist1[2].V, nodelist1[2].L);
									d.SetMemFixed((char*)(unsigned char*)nodelist1[3].V, nodelist1[3].L);
									p.SetMemFixed((char*)(unsigned char*)nodelist1[4].V, nodelist1[4].L);
									q.SetMemFixed((char*)(unsigned char*)nodelist1[5].V, nodelist1[5].L);
									dmp1.SetMemFixed((char*)(unsigned char*)nodelist1[6].V, nodelist1[6].L);
									dmq1.SetMemFixed((char*)(unsigned char*)nodelist1[7].V, nodelist1[7].L);
									iqmp.SetMemFixed((char*)(unsigned char*)nodelist1[8].V, nodelist1[8].L);
									prikey = rsa_key.create_evp(n, e, d, p, q, dmp1, dmq1, iqmp);
									if (!prikey)
									{
										bOK = false;
										RETCode = 500;
										const char* p_c_not_complete = "Not Complete";
										des.Resize(strlen(p_c_not_complete));
										memcpy(des, p_c_not_complete, des.GetSize());
									}
									else
									{
										u_x509 = CBase64::Decode((unsigned char*)KV[ss_c_enccert].c_str(), (long)strlen(KV[ss_c_enccert].c_str()));
										c_x509.SetMemFixed((char*)(unsigned char*)u_x509, u_x509.GetSize());
										x509.setDerCert(c_x509, c_x509.GetSize());
										bool benccreate = _pkcs12.create(KV[ss_c_password].c_str(), prikey, x509, 0, false);
										EVP_PKEY_free(prikey);
										if (!benccreate)
										{
											bOK = false;
											RETCode = 500;
											const char* p_c_not_complete = "Not Complete";
											des.Resize(strlen(p_c_not_complete));
											memcpy(des, p_c_not_complete, des.GetSize());
										}
										else
										{
											CMemBlock<char> m_enccert_pfx = _pkcs12.getDerP12();
											CMemBlock<unsigned char> m_base64_enccert_pfx = CBase64::Encode((unsigned char*)(char*)m_enccert_pfx, (long)m_enccert_pfx.GetSize());
											CMemBlock<char> m_s_enccert_pfx(m_base64_enccert_pfx.GetSize()+1);
											m_s_enccert_pfx[m_base64_enccert_pfx.GetSize()] = 0;
											memcpy(m_s_enccert_pfx, m_base64_enccert_pfx, m_base64_enccert_pfx.GetSize());

											const char* pk1 = "Signcert_pfx";
											const char* pk2 = "Enccert_pfx";
											const char* pv1 = m_s_signcert_pfx;
											const char* pv2 = m_s_enccert_pfx;
											const char  *_k[] = {pk1, pk2}, *_v[] = {pv1, pv2};
											std::string ss_form = genForm(_k, 2, _v, 2);
											signcert_enccert_pfx.Resize(strlen(ss_form.c_str()));
											memcpy(signcert_enccert_pfx, ss_form.c_str(), signcert_enccert_pfx.GetSize());
											bOK = true;
										}
									}
								}
								else
								{
									bOK = false;
									RETCode = 500;
									const char* p_c_not_complete = "Not Complete";
									des.Resize(strlen(p_c_not_complete));
									memcpy(des, p_c_not_complete, des.GetSize());
								}
							}
							else
							{
								bOK = false;
								RETCode = 500;
								const char* p_c_not_complete = "Not Complete";
								des.Resize(strlen(p_c_not_complete));
								memcpy(des, p_c_not_complete, des.GetSize());
							}
						}
					}
				}
			}
		}
	}

	return signcert_enccert_pfx;
}
