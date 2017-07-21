/* CHttpServer.h -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#ifndef _CHTTPSERVER_
#define _CHTTPSERVER_

#include <sys/types.h>
#include "c_util.h"
#include "app_util.h"

#include <vector>
#include <string>
#include <map>

class CHttpServer
{
protected:
	bool bSSL;
private:
	bool bEnable;
	void* Handle_env;
	void* Handle_listen;
	const char* certfile_pem_name;
	const char* prikeyfile_pem_name;
	const char* password;
protected:
	std::vector<void*> m_server_array; 
public:
	CHttpServer(bool bSSL, const char* port, const char* certfile_pem_name=NULL, const char* prikeyfile_pem_name=NULL, const char* password=NULL);
	virtual ~CHttpServer();
protected:
	std::string genForm(const char* KEY[], size_t KEYLen, const char* VALUE[], size_t VALUELen);
	void splitForm(const char* form, std::map<std::string, std::string>& KV);
private:
	void do_filter(CMemBlock<char>& s);
	CMemBlock<char> genGuid();
	CMemBlock<char> getHttpRequestBody(CMemBlock<char> header_body, CMemBlock<char>& url, CMemBlock<char>& content_type, CMemBlock<char>& cookie, bool& bPost);
	CMemBlock<char> addHttpResponseHeader(CMemBlock<char> body, CMemBlock<char> content_type, CMemBlock<char> cookie, CMemBlock<char> des, bool bOK=false, int RETCode=200);
protected:
	virtual bool Send(void* Handle_server, const char* pSendData, size_t stSendDataLen);
	virtual bool Recv(void* Handle_server, CMemBlock<char>& RecvData);
private:
	void do_accept(void);
protected:
	virtual CMemBlock<char> provide_server(CMemBlock<char> bodyData, CMemBlock<char> url, CMemBlock<char> cookie, CMemBlock<char>& content_type, CMemBlock<char>& des, bool& bOK, int& RETCode);
	friend void* server_thread(void *arg);
	friend void server_loop(void* arg);
public:
	int main_server();
	int main_loop();
};


#endif
