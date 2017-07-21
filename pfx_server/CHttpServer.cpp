/* CHttpServer.cpp -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#include "CHttpServer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <uuid/uuid.h>
#include <signal.h>

#include "Interface_CSocket.h"

#define BUF_SIZE_DEF 1024*10
#define LOOP_COUNT 10

CHttpServer::CHttpServer(bool bSSL, const char* port, const char* certfile_pem_name, const char* prikeyfile_pem_name, const char* password):
certfile_pem_name(certfile_pem_name), prikeyfile_pem_name(prikeyfile_pem_name), password(password)
{
	this->bSSL = bSSL;
	bEnable = false;
	Handle_env = 0;
	Handle_listen = 0;

	int _port = 80200;
	if (port && 0<strlen(port))
	{
		_port = atoi(port);
	}
	Handle_env = InitCSSLEnviroment();
	if (Handle_env)
	{
		Handle_listen = InitCSocketListen(_port);
		if (Handle_listen)
		{
			if (DoListen(Handle_listen))
			{
				bEnable = true;
			}
		}
	}
}

CHttpServer::~CHttpServer()
{
	for(std::vector<void*>::iterator it=m_server_array.begin(); it!=m_server_array.end(); it++)
	{
		if (!bSSL)
		{
			ReleaseCSocketServer(*it);
		}
		else
		{
			ReleaseCSSLSocketServer(*it);
		}
	}
	if (Handle_listen)
	{
		ReleaseCSocketListen(Handle_listen);
	}
	if (Handle_env)
	{
		ReleaseCSSLEnviroment(Handle_env);
	}
	
}

std::string CHttpServer::genForm(const char* KEY[], size_t KEYLen, const char* VALUE[], size_t VALUELen)
{
	std::string ret;
	if (!KEY || 0>=KEYLen || !VALUE || 0>=VALUELen)
	{
		return ret;
	}
	size_t len = KEYLen<=VALUELen?KEYLen:VALUELen;
	std::map<std::string, std::string> KV;
	for(size_t i=0; i<len; i++)
	{
		KV.insert(std::pair<std::string, std::string>(KEY[i], VALUE[i]));
	}
	for(std::map<std::string, std::string>::iterator it=KV.begin(); it!=KV.end(); it++)
	{
		ret += (*it).first;
		ret += "=";
		ret += (*it).second;
		ret += "&";
	}
	if (""!=ret)
	{
		ret = ret.substr(0, ret.length()-1);
	}

	return ret;
}


void CHttpServer::splitForm(const char* form, std::map<std::string, std::string>& KV)
{
	if (!form || 0>=strlen(form))
	{
		return;
	}
	size_t pos1 = 0, pos2 = 0;
	const unsigned char* p_tmp = (const unsigned char*)form;
	const unsigned char *ptmp1 = 0, *ptmp2 = 0;
	size_t tmp_count = strlen(form);
	while(0<tmp_count)
	{
		ptmp1 = MemFind((unsigned char*)p_tmp, tmp_count, (unsigned char*)"&", strlen("&"));
		if (((void*)-1)==ptmp1)
		{
			ptmp2 = MemFind((unsigned char*)p_tmp, tmp_count, (unsigned char*)"=", strlen("="));
			if (((void*)-1)!=ptmp2)
			{
				pos2 = ptmp2-p_tmp;
				size_t l1 = pos2, l2 = tmp_count-pos2-1;
				CMemBlock<char> t1(l1+1), t2(l2+1);
				t1[l1] = 0; t2[l2] = 0;
				memcpy(t1, p_tmp, l1);
				memcpy(t2, p_tmp+pos2+1, l2);
				KV.insert(std::pair<std::string, std::string>((char*)t1, (char*)t2));
			}
			break;
		}
		else
		{
			pos1 = ptmp1-p_tmp;
			ptmp2 = MemFind((unsigned char*)p_tmp, pos1, (unsigned char*)"=", strlen("="));
			if (((void*)-1)!=ptmp2)
			{
				pos2 = ptmp2-p_tmp;
				size_t l1 = pos2, l2 = pos1-pos2-1;
				CMemBlock<char> t1(l1+1), t2(l2+1);
				t1[l1] = 0; t2[l2] = 0;
				memcpy(t1, p_tmp, l1);
				memcpy(t2, p_tmp+pos2+1, l2);
				KV.insert(std::pair<std::string, std::string>((char*)t1, (char*)t2));
			}
			p_tmp = p_tmp+pos1+1;
			tmp_count -= (pos1+1);
		}
	}
}

void CHttpServer::do_filter(CMemBlock<char>& s)
{
	size_t count = 0;
	CMemBlock<char> tmp(s.GetSize());
	for(size_t i=0; i<s.GetSize(); i++)
	{
		if (' '!=s[i] && '\r'!=s[i] && '\n'!=s[i])
		{
			tmp[count++] = s[i];
		}
	}
	tmp.Resize(count);
	s = tmp;
}

CMemBlock<char> CHttpServer::getHttpRequestBody(CMemBlock<char> header_body, CMemBlock<char>& url, CMemBlock<char>& content_type, CMemBlock<char>& cookie, bool& bPost)
{
	CMemBlock<char> ret;
	bool bProtocol = true;
	size_t pos1 = 0, pos2 = 0;
	const unsigned char *ptmp1 = 0, *ptmp2 = 0;
	const unsigned char* p_tmp = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"GET", strlen("GET"));
	if (((void*)-1)!=p_tmp)
	{
		bPost = false;
	}
	else
	{
		p_tmp = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"POST", strlen("POST"));
		if (((void*)-1)!=p_tmp)
		{
			bPost = true;
		}
		else
		{
			bPost = false;
			bProtocol = false;
		}
	}
	if (!bProtocol)
	{
		return ret;
	}
	if (!bPost)
	{
		ptmp1 = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"GET", strlen("GET"));
		ptmp2 = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"?", strlen("?"));
		if (((void*)-1)!=ptmp1 && ((void*)-1)!=ptmp2)
		{
			pos1 = ptmp1-(unsigned char*)(char*)header_body;
			pos2 = ptmp2-(unsigned char*)(char*)header_body;
			if (pos1<pos2)
			{
				size_t len = pos2-pos1-3;
				CMemBlock<char> s_tmp(len);
				memcpy(s_tmp, ptmp1+3, len);
				do_filter(s_tmp);
				if (0<s_tmp.GetSize())
				{
					url.Resize(s_tmp.GetSize());
					memcpy(url, s_tmp, s_tmp.GetSize());
				}
			}
			ptmp1 = ptmp2+1;
			ptmp2 = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"HTTP/", strlen("HTTP/"));
			if (((void*)-1)!=ptmp2)
			{
				pos1 = ptmp1-(unsigned char*)(char*)header_body;
				pos2 = ptmp2-(unsigned char*)(char*)header_body;
				if (pos1<pos2)
				{
					size_t len = pos2-pos1;
					CMemBlock<char> s_tmp(len);
					memcpy(s_tmp, ptmp1, len);
					do_filter(s_tmp);
					if (0<s_tmp.GetSize())
					{
						ret = s_tmp;
					}
				}
			}
			ptmp1 = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"Cookie:", strlen("Cookie:"));
			if (((void*)-1)!=ptmp1)
			{
				pos1 = ptmp1-(unsigned char*)(char*)header_body;
				ptmp2 = MemFind(ptmp1, header_body.GetSize()-pos1, (unsigned char*)"\r\n", strlen("\r\n"));
				pos2 = ptmp2-ptmp1+pos1;
				if (pos1<pos2)
				{
					size_t len = pos2-pos1-strlen("Cookie:");
					CMemBlock<char> s_tmp(len);
					memcpy(s_tmp, ptmp1+strlen("Cookie:"), len);
					do_filter(s_tmp);
					if (0<s_tmp.GetSize())
					{
						cookie = s_tmp;
					}
				}
			}
		}
	}
	else
	{
		ptmp1 = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"POST", strlen("POST"));
		ptmp2 = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"HTTP/", strlen("HTTP/"));
		if (((void*)-1)!=ptmp1 && ((void*)-1)!=ptmp2)
		{
			pos1 = ptmp1-(unsigned char*)(char*)header_body;
			pos2 = ptmp2-(unsigned char*)(char*)header_body;
			if (pos1<pos2)
			{
				size_t len = pos2-pos1-4;
				CMemBlock<char> s_tmp(len);
				memcpy(s_tmp, ptmp1+4, len);
				do_filter(s_tmp);
				if (0<s_tmp.GetSize())
				{
					url.Resize(s_tmp.GetSize());
					memcpy(url, s_tmp, s_tmp.GetSize());
				}
			}
			ptmp1 = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"Content-Type:", strlen("Content-Type:"));
			if (((void*)-1)!=ptmp1)
			{
				pos1 = ptmp1-(unsigned char*)(char*)header_body;
				ptmp2 = MemFind(ptmp1, header_body.GetSize()-pos1, (unsigned char*)"\r\n", strlen("\r\n"));
				pos2 = ptmp2-ptmp1+pos1;
				if (pos1<pos2)
				{
					size_t len = pos2-pos1-strlen("Content-Type:");
					CMemBlock<char> s_tmp(len);
					memcpy(s_tmp, ptmp1+strlen("Content-Type:"), len);
					do_filter(s_tmp);
					if (0<s_tmp.GetSize())
					{
						content_type = s_tmp;
					}
				}
			}
			ptmp1 = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"Cookie:", strlen("Cookie:"));
			if (((void*)-1)!=ptmp1)
			{
				pos1 = ptmp1-(unsigned char*)(char*)header_body;
				ptmp2 = MemFind(ptmp1, header_body.GetSize()-pos1, (unsigned char*)"\r\n", strlen("\r\n"));
				pos2 = ptmp2-ptmp1+pos1;
				if (pos1<pos2)
				{
					size_t len = pos2-pos1-strlen("Cookie:");
					CMemBlock<char> s_tmp(len);
					memcpy(s_tmp, ptmp1+strlen("Cookie:"), len);
					do_filter(s_tmp);
					if (0<s_tmp.GetSize())
					{
						cookie = s_tmp;
					}
				}
			}
			ptmp1 = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"Content-Length:", strlen("Content-Length:"));
			if (((void*)-1)!=ptmp1)
			{
				pos1 = ptmp1-(unsigned char*)(char*)header_body;
				ptmp2 = MemFind(ptmp1, header_body.GetSize()-pos1, (unsigned char*)"\r\n", strlen("\r\n"));
				pos2 = ptmp2-ptmp1+pos1;
				if (pos1<pos2)
				{
					size_t len = pos2-pos1-strlen("Content-Length:");
					CMemBlock<char> s_tmp(len);
					memcpy(s_tmp, ptmp1+strlen("Content-Length:"), len);
					do_filter(s_tmp);
					if (0<s_tmp.GetSize())
					{
						size_t lindex = s_tmp.GetSize();
						s_tmp.Resize(lindex+1);
						s_tmp[lindex] = 0;
						int count = 0;
						if (0!=strcmp("", s_tmp))
						{
							count = atoi(s_tmp);
						}
						ptmp1 = MemFind((unsigned char*)(char*)header_body, header_body.GetSize(), (unsigned char*)"\r\n\r\n", strlen("\r\n\r\n"));
						if (0<count && ((void*)-1)!=ptmp1)
						{
							pos1 = ptmp1-(unsigned char*)(char*)header_body;
							if (count==(header_body.GetSize()-pos1-4))
							{
								CMemBlock<char> s_tmp(count);
								memcpy(s_tmp, ptmp1+4, count);
								ret = s_tmp;
							}
						}
					}
				}
			}
		}
	}

	return ret;
}

CMemBlock<char> CHttpServer::addHttpResponseHeader(CMemBlock<char> body, CMemBlock<char> content_type, CMemBlock<char> cookie, CMemBlock<char> des, bool bOK, int RETCode)
{
	CMemBlock<char> ret;
	std::string s_tmp = "";
	if (!bOK)
	{
		s_tmp += "HTTP/1.1 ";
		char buf[256] = {0};
		sprintf(buf, "%d", RETCode);
		s_tmp += buf;
		if (0>=des.GetSize())
		{
			s_tmp += " FAILT";
		}
		else
		{
			s_tmp += " ";
			memcpy(buf, des, des.GetSize());
			buf[des.GetSize()] = 0;
			s_tmp += buf;
		}
		//s_tmp += "\r\n";
	}
	else
	{
		s_tmp += "HTTP/1.1 200 OK\r\n";
		size_t count = content_type.GetSize();
		CMemBlock<char> tmp(count+1);
		tmp[count] = 0;
		memcpy(tmp, content_type, count);
		s_tmp += "Content-Type:";
		s_tmp += (char*)tmp;
		s_tmp += "\r\n";
		s_tmp += "Content-Length:";
		size_t count_body = body.GetSize();
		char buf[256] = {0};
		sprintf(buf, "%d", (int)count_body);
		s_tmp += buf;
		s_tmp += "\r\n";
		if (0<cookie.GetSize())
		{
			tmp.Resize(cookie.GetSize()+1);
			tmp[cookie.GetSize()] = 0;
			memcpy(tmp, cookie, cookie.GetSize());
			s_tmp += "Cookie:";
			s_tmp += (char*)tmp;
			s_tmp += "\r\n";
		}

		s_tmp += "\r\n";
		CMemBlock<char> body_copy(count_body+1);
		body_copy[count_body] = 0;
		memcpy(body_copy, body, count_body);
		s_tmp += (char*)body_copy;
	}
	size_t len = strlen(s_tmp.c_str());
	ret.Resize(len);
	memcpy(ret, s_tmp.c_str(), len);

	return ret;
}

bool CHttpServer::Send(void* Handle_server, const char* pSendData, size_t stSendDataLen)
{
	if (!pSendData || 0==stSendDataLen)
	{
		return true;
	}
	bool ret = true;
	size_t count = stSendDataLen;
	size_t send_count = 0; 
	size_t loop_count = LOOP_COUNT;
	while(1)
	{
		CMemBlock<char> buf(BUF_SIZE_DEF);
		int len = 0;
		if (count<=buf.GetSize())
		{
			memcpy(buf, pSendData+send_count, count);
			if (!bSSL)
			{
				len = ServerSend(Handle_server, buf, (int)count);
			}
			else
			{
				len = SSLServerSend(Handle_server, buf, (int)count);
			}
			if (-1==len)
			{
				//printf("SEND %s\n", "send error");
				ret = false;
				break;
			}
			else if (0==len)
			{
				if (0==loop_count)
				{
					//printf("SEND %s\n", "send peer busying");
					ret = false;
					break;
				}
				loop_count--;
				continue;
			}
			loop_count = LOOP_COUNT;
			count -= len;
			send_count += len;
			if (0==count)
			{
				break;
			}
		}
		else
		{
			memcpy(buf, pSendData+send_count, buf.GetSize());
			if (!bSSL)
			{
				len = ServerSend(Handle_server, buf, (int)buf.GetSize());
			}
			else
			{
				len = SSLServerSend(Handle_server, buf, (int)buf.GetSize());
			}
			if (-1==len)
			{
				//printf("SEND %s\n", "send error");
				ret = false;
				break;
			}
			else if (0==len)
			{
				if (0==loop_count)
				{
					//printf("SEND %s\n", "send peer busying");
					ret = false;
					break;
				}
				loop_count--;
				continue;
			}
			loop_count = LOOP_COUNT;
			count -= len;
			send_count += len;
		}
	}

	return ret;
}

bool CHttpServer::Recv(void* Handle_server, CMemBlock<char>& RecvData)
{
	bool ret = true;
	int loop_count = LOOP_COUNT;
	while(1)
	{
		CMemBlock<char> buf(BUF_SIZE_DEF);
		int len = 0;
		if (!bSSL)
		{
			len = ServerRecv(Handle_server, buf, buf.GetSize());
		}
		else
		{
			len = SSLServerRecv(Handle_server, buf, buf.GetSize());
		}
		if (-2==len)
		{
			if (0==loop_count)
			{
				break;
			}
			loop_count--;
			continue;
		}
		else if (-1==len)
		{
			//printf("RECV %s\n", "recv error");
			ret = false;
			break;
		}
		else if (0==len)
		{
			//printf("RECV %s\n", "recv peer closed");
			ret = false;
			break;
		}
		else
		{
			buf.Resize((size_t)len);
			RecvData += buf;
			loop_count = LOOP_COUNT;
		}
	}

	return ret;
}

void CHttpServer::do_accept(void)
{
	if (bEnable)
	{
		void* Handle_server = NULL;
		if (!bSSL)
		{
			Handle_server = InitCSocketServer(Handle_listen);
		}
		else
		{
			Handle_server = InitCSSLSocketServer(Handle_listen, certfile_pem_name, prikeyfile_pem_name, password);
		}
		if (Handle_server)
		{
			if (!bSSL)
			{
				DoServerAccept(Handle_server);
				if (!IsServerAccept(Handle_server))
				{
					ReleaseCSocketServer(Handle_server);
				}
				else
				{
					//printf("%s\n", "Accept is succeed");
					m_server_array.push_back(Handle_server);
				}
			}
			else
			{
				DoSSLServerAccept(Handle_server);
				if (!IsSSLServerAccept(Handle_server))
				{
					ReleaseCSSLSocketServer(Handle_server);
				}
				else
				{
					//printf("%s\n", "Accept is succeed");
					m_server_array.push_back(Handle_server);
				}
			}
		}
	}
}

CMemBlock<char> CHttpServer::provide_server(CMemBlock<char> bodyData, CMemBlock<char> url, CMemBlock<char> cookie, CMemBlock<char>& content_type, CMemBlock<char>& des, bool& bOK, int& RETCode)
{
	CMemBlock<char> ret;

	return ret;
}

void printids(const char *s)  
{  
    pid_t pid;  
    pthread_t tid;  
  
    pid = getpid();  
    tid = pthread_self();  
    printf("%s pid %u tid %u (0x%x)\n", s, (unsigned int)pid, (unsigned int)tid, (unsigned int)tid);  
  
}  

CMemBlock<char> CHttpServer::genGuid()
{
	CMemBlock<char> guid(32);
	char c_buf[3] = {0};
	uuid_t uu;
	size_t i;
	uuid_generate(uu);
	for(i=0; i<16; i++)
	{
		sprintf(c_buf, "%02X", uu[(int)i]);
		memcpy(guid+2*i, c_buf, 2);
	}

	return guid;
}

static pthread_cond_t cond;  
static pthread_mutex_t mutex;  
static int flag = 1;  
void* server_thread(void *arg)  
{ 
	printids("new thread:"); 
	CHttpServer* server = (CHttpServer*)arg;
	if (!server)
	{
		return ((void*)0);
	}

	struct timeval now;  
  	struct timespec outtime;  
  	pthread_mutex_lock(&mutex);  
	while(flag)
	{
		// printf("*****monitor for main thread\n");  
    	gettimeofday(&now, NULL);  
    	outtime.tv_sec = 0;//now.tv_sec+5;  
    	outtime.tv_nsec = 50;//now.tv_usec*1000;  
    	pthread_cond_timedwait(&cond, &mutex, &outtime);

		server->do_accept();
		// printf("%s\n", "do accept*****"); 
		bool bRecv = false;
		for(std::vector<void*>::iterator it=server->m_server_array.begin(); it!=server->m_server_array.end();)
		{
			// printf("%s\n", "do busyness*****");  
			CMemBlock<char> rdata;
			bRecv = server->Recv(*it, rdata);
			if (!bRecv)
			{
				if (!server->bSSL)
				{
					//printf("%s\n", "Recv Connect is closed");
					ReleaseCSocketServer(*it);
				}
				else
				{
					//printf("%s\n", "Recv Connect is closed");
					ReleaseCSSLSocketServer(*it);
				}
				it = server->m_server_array.erase(it);
			}
			else
			{
				if (0<rdata.GetSize())
				{
					time_t t_recv_end;
					time(&t_recv_end);
					//printf("recv   end: %lld\n", (long long int)t_recv_end);
					bool bPost = true;
					CMemBlock<char> url;
					CMemBlock<char> content_type;
					CMemBlock<char> des;
					CMemBlock<char> cookie;
					bool bOK = false;
					int RETCode = 200;
					CMemBlock<char> body = server->getHttpRequestBody(rdata, url, content_type, cookie, bPost);
					if (0==body.GetSize() && 0==url.GetSize() && 0==content_type.GetSize() && !bPost)
					{
						continue;
					}
					if (0==cookie.GetSize())
					{
						cookie = server->genGuid();
					}
					CMemBlock<char> res = server->provide_server(body, url, cookie, content_type, des, bOK, RETCode);
					CMemBlock<char> hd = server->addHttpResponseHeader(res, content_type, cookie, des, bOK, RETCode);
					if (0<hd.GetSize())
					{
						bool bSend = server->Send(*it, hd, hd.GetSize());
						if (!bSend)
						{
							if (!server->bSSL)
							{
								//printf("%s\n", "Send Connect is closed");
								ReleaseCSocketServer(*it);
							}
							else
							{
								//printf("%s\n", "Send Connect is closed");
								ReleaseCSSLSocketServer(*it);
							}
							it = server->m_server_array.erase(it);
						}
						else
						{
							time_t t_send_end;
							time(&t_send_end);
							//printf("send   end: %lld\n", (long long int)t_send_end);
							it++;
						}
					}
					else
					{
						it++;
					}
				}
				else
				{
					it++;
				}
			}
		}
	}
	pthread_mutex_unlock(&mutex);  
  	printf("cond thread exit\n");  

    return ((void*)0);  
}

bool bRun = true;
void SignalHandler(int iSignNum)
{
    printf("capture signal number:%d\n",iSignNum);
    bRun = false;
}

void server_loop(void* arg)
{
	printids("new thread:"); 
	CHttpServer* server = (CHttpServer*)arg;
	if (!server)
	{
		return;
	}
	while(bRun)
	{
		signal(SIGINT, SignalHandler);
		server->do_accept();
		// printf("%s\n", "do accept*****"); 
		bool bRecv = false;
		for(std::vector<void*>::iterator it=server->m_server_array.begin(); it!=server->m_server_array.end();)
		{
			//printf("%s\n", "do busyness*****");  
			CMemBlock<char> rdata;
			bRecv = server->Recv(*it, rdata);
			if (!bRecv)
			{
				if (!server->bSSL)
				{
					printf("%s\n", "Peer Connect is closed");
					ReleaseCSocketServer(*it);
				}
				else
				{
					printf("%s\n", "Peer Connect is closed");
					ReleaseCSSLSocketServer(*it);
				}
				it = server->m_server_array.erase(it);
			}
			else
			{
				if (0<rdata.GetSize())
				{
					//printf("recv data:%s\n", (char*)rdata);
					time_t t_recv_end;
					time(&t_recv_end);
					//printf("recv   end: %lld\n", (long long int)t_recv_end);
					bool bPost = true;
					CMemBlock<char> url;
					CMemBlock<char> content_type;
					CMemBlock<char> des;
					CMemBlock<char> cookie;
					bool bOK = false;
					int RETCode = 200;
					CMemBlock<char> req_body = server->getHttpRequestBody(rdata, url, content_type, cookie, bPost);
					if (0==req_body.GetSize() && 0==url.GetSize() && 0==content_type.GetSize() && !bPost)
					{
						it = server->m_server_array.erase(it);
						continue;
					}
					if (0==cookie.GetSize())
					{
						cookie = server->genGuid();
					}
					if (0<cookie.GetSize())
					{
						//printf("session: %s\n", (char*)cookie);
					}
					CMemBlock<char> res_body = server->provide_server(req_body, url, cookie, content_type, des, bOK, RETCode);
					CMemBlock<char> hd = server->addHttpResponseHeader(res_body, content_type, cookie, des, bOK, RETCode);
					if (0<hd.GetSize())
					{
						bool bSend = server->Send(*it, hd, hd.GetSize());
					}
					if (!server->bSSL)
					{
						//printf("%s\n", "Send Connect is closed");
						ReleaseCSocketServer(*it);
					}
					else
					{
						//printf("%s\n", "Send Connect is closed");
						ReleaseCSSLSocketServer(*it);
					}
					it = server->m_server_array.erase(it);
				}
				else
				{
					it++;
				}
			}
		}
	}
}

int CHttpServer::main_server()
{
	printids("main thread:"); 
	pthread_t ntid;
	int error = 0;
	pthread_mutex_init(&mutex, NULL);  
  	pthread_cond_init(&cond, NULL);  
    if ((error=pthread_create(&ntid, NULL, server_thread, this)))  
    {  
        printf("can't create thread: %s\n", strerror(error));  
        return 1;  
    }
    char any_char_for_exit = getchar();
    pthread_mutex_lock(&mutex);  
  	flag = 0;  
  	pthread_cond_signal(&cond);  
  	pthread_mutex_unlock(&mutex);  
  	printf("Wait for thread to exit\n");  
  	pthread_join(ntid, NULL);  
  	printf("Bye\n");  

    return 0; 
}


int CHttpServer::main_loop()
{
	server_loop(this);
}
