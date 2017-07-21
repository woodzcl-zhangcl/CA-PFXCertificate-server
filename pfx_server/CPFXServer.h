/* CPFXServer.h -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#ifndef _CPFXSERVER_
#define _CPFXSERVER_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <vector>
#include <string>
#include <map>

#include "c_util.h"
#include "app_util.h"

#include "CHttpServer.h"
#include "cs_openssl_init.h"

struct PFXSession
{
	CMemBlock<char> id;
	time_t tt_create;
	CMemBlock<char> n;
	CMemBlock<char> e;
	CMemBlock<char> d;
	CMemBlock<char> p;
	CMemBlock<char> q;
	CMemBlock<char> dmp1;
	CMemBlock<char> dmq1;
	CMemBlock<char> iqmp;
};

class CPFXServer:public CHttpServer
{
	cs_openssl_init coit;
	std::vector<PFXSession> m_session;
public:
	CPFXServer(bool bSSL, const char* port, const char* certfile_pem_name=NULL, const char* prikeyfile_pem_name=NULL, const char* password=NULL);
	virtual ~CPFXServer();
protected:
	virtual CMemBlock<char> provide_server(CMemBlock<char> bodyData, CMemBlock<char> url, CMemBlock<char> cookie, CMemBlock<char>& content_type, CMemBlock<char>& des, bool& bOK, int& RETCode);
private:
	bool findSession(CMemBlock<char> ID, PFXSession& session);
	void insertSession(PFXSession& session);
	void deleteSession(CMemBlock<char> ID);
	bool isSessionAvailable(CMemBlock<char> ID);
	void autoRemoveSession();
private:
	CMemBlock<unsigned char> get_encode_oid(const long* l_oid, size_t s_t_len);
	CMemBlock<unsigned char> get_encode_oid(const char* s_oid);
	CMemBlock<char> gen_rsa_p10(void* p_rsa_key, const char* p_c_digest_alg_oid);
	CMemBlock<char> get_rsa_encpubkey(void* p_rsa_key);
protected:
	CMemBlock<char> get_rsa_p10_encpubkey(CMemBlock<char> bodyData, CMemBlock<char> cookie, CMemBlock<char>& content_type, CMemBlock<char>& des, bool& bOK, int& RETCode);
	CMemBlock<char> get_rsa_signcert_pfx(CMemBlock<char> bodyData, CMemBlock<char> cookie, CMemBlock<char>& content_type, CMemBlock<char>& des, bool& bOK, int& RETCode);
	CMemBlock<char> get_rsa_signcert_enccert_pfx(CMemBlock<char> bodyData, CMemBlock<char> cookie, CMemBlock<char>& content_type, CMemBlock<char>& des, bool& bOK, int& RETCode);

};

#endif
