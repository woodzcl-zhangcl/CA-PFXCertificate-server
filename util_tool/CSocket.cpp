/* CSocket.cpp -- internal utility state
 * Copyright (C++) forever zhangcl 791398105@qq.com
 * welcome to use freely
 */


#include "CSocket.h"
#include "c_util.h"

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

/*
* ÒÑŸ­Á¬œÓµÄsocket£¬ÉèÖÃ³¬Ê±£º
* int nNetTimeout = 5000; //1Ãë
* setsockopt(m_sot, SOL_SOCKET, SO_SNDTIMEO, (char*)&nNetTimeout, sizeof(int));
* setsockopt(m_sot, SOL_SOCKET, SO_RCVTIMEO, (char*)&nNetTimeout, sizeof(int));
*/

/*
* µ±¿Í»§¶ËÈ¥Ö÷¶¯Á¬œÓ·þÎñ¶ËµÄÊ±ºò£šTCP£©£¬Ä¬ÈÏÊÇ²»ÐèÒªÖž¶š£¬±ŸµØµÄipÓë¶Ë¿ÚµÄ£¬²Ù×÷ÏµÍ³»á×Ô¶¯žøÄã·ÖÅä¶Ë¿Ú£¬È»ºóžùŸÝÂ·ÓÉ×Ô¶¯Ñ¡Ôñ³ö¿Ú¡£
* µ«ÊÇµ±ÄãÏëÖ÷¶¯žùŸÝ²»Í¬µÄÊýŸÝÈ¥Ñ¡Ôñ²»Í¬µÄÍø¿š·¢ËÍÊ±£¬ÎÒÃÇÓŠžÃÔõÃŽ×öÄØ¡£
* Žð°žºÜŒòµ¥£º
* SOCKADDR_IN addrSelf;//±ŸµØµØÖ·  
* addrSelf.sin_addr.s_addr = inet_addr("192.168.1.110");//Öž¶šÍø¿šµÄµØÖ·  
* addrSelf.sin_family = AF_INET;   addrSelf.sin_port = htons(20000);//±ŸµØ¶Ë¿Ú  
* if( -1 == bind(sockClient[i],(SOCKADDR*)&addrSelf,sizeof(SOCKADDR)))//°ÑÍø¿šµØÖ·Ç¿ÐÐ°ó¶šµœSoket
* {
* 	 °ó¶š³É¹Š
* }
*/

#define SOCKET_ERROR (-1)

#define ToSSL_CTX(p)    ((SSL_CTX*)p)
#define ToSSL(p)        ((SSL*)p)
#define ToSSL_METHOD(p) ((const SSL_METHOD*)p)


bool IsReadable(int sot, bool* pVal)
{
	bool bRet = true;
	if (pVal)
		*pVal = false;
	int ret;
	struct timeval tv = {0, 1}; 
	fd_set rset;
	FD_ZERO(&rset); 
	FD_SET(sot, &rset);
	ret = select(sot+1, &rset, NULL, NULL, &tv);
	if (0 == ret)
	{
		//timeout
	}
	else if (SOCKET_ERROR == ret)
	{
		//error
		bRet = false;
	}
	else
	{
		if (FD_ISSET(sot, &rset))
		{
			if (pVal)
				*pVal = true;
		}
	}

	return bRet;
}

bool IsWritable(int sot, bool* pVal)
{
	bool bRet = true;
	if (pVal)
		*pVal = false;
	int ret;
	struct timeval tv = {0, 1}; 
	fd_set  rset = {0};
	FD_SET(sot, &rset);
	ret = select(sot+1, NULL, &rset, NULL, &tv);
	if (0 == ret)
	{
		//timeout
	}
	else if (SOCKET_ERROR == ret)
	{
		//error
		bRet = false;
	}
	else
	{
		if (FD_ISSET(sot, &rset))
		{
			if (pVal)
				*pVal = true;
		}
	}

	return bRet;
}

CSocket::CSocket()
{
	m_sot = 0;
}

CSocket::~CSocket()
{
	if (0 < m_sot)
	{
		close(m_sot);
	}
}

int CSocket::GetSocket()
{
	return m_sot;
}
bool CSocket::IsReadable(bool* pVal)
{
	return ::IsReadable(m_sot, pVal);
}

bool CSocket::IsWritable(bool* pVal)
{
	return ::IsWritable(m_sot, pVal);
}

int CSocket::Send(const char* pSendData, int len)
{
	int ret = 0;
	bool bWritable;
	if (!IsWritable(&bWritable))
	{
		ret = -1;
	}
	if (bWritable)
	{
		ret = send(m_sot, pSendData, len, 0);
	}

	return ret;
}

int CSocket::Recv(char* pRecvData, int len)
{
	int ret = -2;
	bool bReadable;
	if (!IsReadable(&bReadable))
	{
		ret = -1;
	}
	if (bReadable)
	{
		ret = recv(m_sot, pRecvData, len, 0);
	}

	return ret;
}

CSocketListen::CSocketListen(int Port, bool noneBlock)
{
	m_port = 0;
	if (0 != Port)
	{
		m_port = Port;
	}
	m_noneBlock = noneBlock;
	bListen = false;
}

CSocketListen::~CSocketListen()
{
}

bool CSocketListen::DoListen(int c)
{
	bool ret = false;
	if (!bListen && 0 != m_port)
	{
		while(1)
		{
			m_sot = socket(AF_INET, SOCK_STREAM, 0);
			if (-1 == m_sot)
				break;
			int on = 1;  
    		if (0 > setsockopt(m_sot, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
    		{
    			close(m_sot);
    			m_sot = -1;
    			break;
    		}
			struct sockaddr_in sa_serv;
			memset(&sa_serv, 0, sizeof(sa_serv));
			sa_serv.sin_family      = AF_INET;
			sa_serv.sin_addr.s_addr = INADDR_ANY/*inet_addr("10.20.61.108")*/;
			sa_serv.sin_port        = htons (m_port);
			if (-1 == bind(m_sot, (struct sockaddr*) &sa_serv, sizeof (sa_serv)))
			{
				close(m_sot);
				m_sot = -1;
				break;
			}
			if (-1 == listen(m_sot, c))
			{
				close(m_sot);
				m_sot = -1;
				break;
			}
			bListen = true;
			ret = true;
			break;
		}
	}

	return ret;
}

bool CSocketListen::IsListen()
{
	return bListen;
}

int CSocketListen::DoAccept(struct sockaddr_in* psa_cli)
{
	int sot = -2;
	struct sockaddr_in sa_cli = {0};
	struct sockaddr_in* pSA_CLI = &sa_cli;
	if (psa_cli)
		pSA_CLI = psa_cli;
	size_t client_len = sizeof(struct sockaddr_in);
	bool bReadable = false;
	if (!IsReadable(&bReadable))
	{
		sot = -1;
	}
	else
	{
		if (bReadable || !m_noneBlock)
			sot = accept(m_sot, (struct sockaddr*)pSA_CLI, (socklen_t*)&client_len);
	}

	return sot;
}

CSocketServer::CSocketServer(CSocketListen* pListen)
{
	m_pListen = pListen;
	memset(&sa_cli, 0, sizeof(struct sockaddr_in));
	bAccept = false;
}

CSocketServer::~CSocketServer()
{
}

const struct sockaddr_in* CSocketServer::Getsockaddr_in()
{
	return &sa_cli;
}

int CSocketServer::DoAccept()
{
	m_sot = m_pListen->DoAccept(&sa_cli);
	if (0 < m_sot)
	{
		bAccept = true;
		//printf("socket server accept %d\n", m_sot);
	}
	
	return m_sot;
}

bool CSocketServer::IsAccept()
{
	return bAccept;
}

CSocketClient::CSocketClient(const char* IP, int Port)
{
	if (IP && 0 < strlen(IP))
	{
		strcpy(m_ip, IP);
	}
	if (0 != Port)
	{
		m_port = Port;
	}
	bConnect = false;
}

CSocketClient::~CSocketClient()
{
}

int CSocketClient::DoConnect(int to_second)
{
	int ret = -1;
	if (!bConnect)
	{
		while(1)
		{
			m_sot = socket(AF_INET, SOCK_STREAM, 0);
			if (-1 == m_sot)
			{
				m_sot = 0;
				break;
			}

			fd_set rfd;      //ÃèÊö·ûŒ¯ Õâžöœ«²âÊÔÁ¬œÓÊÇ·ñ¿ÉÓÃ
			struct timeval timeout;  //Ê±Œäœá¹¹Ìå
			FD_ZERO(&rfd);//ÏÈÇå¿ÕÒ»žöÃèÊö·ûŒ¯
			timeout.tv_sec = to_second;//Ãë
			timeout.tv_usec = 0;//Ò»°ÙÍò·ÖÖ®Ò»Ãë£¬Î¢Ãë
 
			int flags = fcntl(m_sot, F_GETFL, 0);
			fcntl(m_sot, F_SETFL, flags|O_NONBLOCK);

			struct sockaddr_in sa;
			memset(&sa, 0, sizeof(sa));
			sa.sin_family      = AF_INET;
			sa.sin_addr.s_addr = inet_addr(m_ip); 
			sa.sin_port        = htons(m_port); 
			/*if (-1 == connect(m_sot, (struct sockaddr*)&sa, sizeof(sa)))
			{
				close(m_sot);
				m_sot = 0;
				break;
			}*/
			connect(m_sot, (struct sockaddr*)&sa, sizeof(sa));
			FD_SET(m_sot, &rfd);
			int r = select(0, 0, &rfd, 0, &timeout);
			if (0>=r)
			{
				close(m_sot);
				m_sot = 0;
				break;
			}
			flags = fcntl(m_sot, F_GETFL, 0);
			fcntl(m_sot, F_SETFL, flags&(~O_NONBLOCK));
			bConnect = true;
			ret = m_sot;
			break;
		}
	}

	return ret;
}

bool CSocketClient::IsConnect()
{
	return bConnect;
}

CSSLEnviroment::CSSLEnviroment()
{
	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();
}

CSSLEnviroment::~CSSLEnviroment()
{
	CONF_modules_unload(1);        //for conf  
    EVP_cleanup();                 //For EVP  
    ENGINE_cleanup();              //for engine  
    CRYPTO_cleanup_all_ex_data();  //generic   
    // ERR_remove_thread_state(0);    //for ERR  
    ERR_free_strings();            //for ERR  	
}

CSSLSocket::CSSLSocket(int& refsot, const char* certname_pem, const char* prikeyname_pem, const char* password) : m_refsot(refsot)
{
	memset(cert_pem_file, 0, sizeof(cert_pem_file));
	memset(prikey_pem_file, 0, sizeof(prikey_pem_file));
	memset(m_password, 0, sizeof(m_password));
	if (certname_pem && 0 < strlen(certname_pem))
	{
		strcpy(cert_pem_file, certname_pem);
	}
	if (prikeyname_pem && 0 < strlen(prikeyname_pem))
	{
		strcpy(prikey_pem_file, prikeyname_pem);
	}
	if (password && 0 < strlen(password))
	{
		strcpy(m_password, password);
	}
	ctx = NULL;
	ssl = NULL;
	meth = NULL;
	bInit = false;
}

CSSLSocket::~CSSLSocket()
{
	if (ssl)
		SSL_free(ToSSL(ssl));
	if (ctx)
		SSL_CTX_free(ToSSL_CTX(ctx));
}

bool CSSLSocket::UseMethod()
{
	bool ret = false;
	return ret;
}

bool CSSLSocket::LoadFile(const char* certname_pem, const char* prikeyname_pem, const char* password)
{
	bool ret = false;
	if (!certname_pem && !prikeyname_pem)
	{
		ret = true;
	}
	else if (
		certname_pem
		&& strlen(certname_pem) == 0
		&& prikeyname_pem
		&& strlen(prikeyname_pem) == 0
		)
	{
		ret = true;
	}
	else
	{
		CMemBlock<char> certfile(256), prikeyfile(256);
		certfile.Zero();prikeyfile.Zero();
		CMemBlock<char> cur_dir(256);
    	getcwd(cur_dir, cur_dir.GetSize());
    	strcpy(certfile, cur_dir);
    	strcpy(prikeyfile, cur_dir);
		if (certname_pem && strlen(certname_pem) > 0)
		{
			strcat(certfile, "/");
			strcat(certfile, certname_pem);
			//printf("certfile: %s\n", (char*)certfile);
		}
		if (prikeyname_pem && strlen(prikeyname_pem) > 0)
		{
			strcat(prikeyfile, "/");
			strcat(prikeyfile, prikeyname_pem);
			//printf("prikeyfile: %s\n", (char*)prikeyfile);
		}
		if (0 < strlen(password))
		{
			SSL_CTX_set_default_passwd_cb_userdata(ToSSL_CTX(ctx), (void*)const_cast<char*>(password));
		}
		if (certfile.GetSize() > 0 && prikeyfile.GetSize() > 0)
		{
			if (SSL_CTX_use_certificate_file(ToSSL_CTX(ctx), certfile, SSL_FILETYPE_PEM) > 0)
			{
				if (SSL_CTX_use_PrivateKey_file(ToSSL_CTX(ctx), prikeyfile, SSL_FILETYPE_PEM) > 0)
				{
					if (SSL_CTX_check_private_key(ToSSL_CTX(ctx))) 
					{
						ret = true;
					}
				}
			}
		}
	}

	return ret;
}

bool CSSLSocket::Init()
{
	bool ret = false;
	if (!bInit && UseMethod())
	{
		ctx = SSL_CTX_new(ToSSL_METHOD(meth));
		if (ctx)
		{
			if (!LoadFile(cert_pem_file, prikey_pem_file, m_password))
			{
				SSL_CTX_free(ToSSL_CTX(ctx));
				ctx = NULL;
			}
			else
			{
				ssl = SSL_new(ToSSL_CTX(ctx));
				if (!ssl)
				{
					SSL_CTX_free(ToSSL_CTX(ctx));
					ctx = NULL;
				}
				else
				{
					SSL_set_fd(ToSSL(ssl), m_refsot);
					bInit = true;
					ret = true;
				}
			}
		}
	}

	return ret;
}

bool CSSLSocket::GetErrorMsg(char* pErrMsg, int* plErrMsg)
{
	bool ret = false;
	unsigned long ulErr = ERR_get_error();
	char szErrMsg[1024] = {0};
	char *pTmp = NULL;
	pTmp = ERR_error_string(ulErr, szErrMsg); 
	size_t len = strlen(pTmp);
	if (!pErrMsg && plErrMsg)
	{
		*plErrMsg = len+1;
		ret = true;
	}
	else if (pErrMsg && plErrMsg && (*plErrMsg) >= (int)(len+1))
	{
		memcpy(pErrMsg, pTmp, len);
		pErrMsg[len] = 0;
		ret = true;
	}

	return ret;
}

int CSSLSocket::SSLSend(const char* pSendData, int len)
{
	int ret = 0;
	bool bWritable;
	if (!IsWritable(m_refsot, &bWritable))
	{
		ret = -1;
	}
	if (bWritable)
	{
		ret = SSL_write(ToSSL(ssl), pSendData, len);
	}

	return ret;
}

int CSSLSocket::SSLRecv(char* pRecvData, int len)
{
	int ret = -2;
	bool bReadable;
	if (!IsReadable(m_refsot, &bReadable))
	{
		return ret = -1;
	}
	if (bReadable)
	{
		ret = SSL_read(ToSSL(ssl), pRecvData, len);
	}

	return ret;
}

CSSLSocketServer::CSSLSocketServer(CSocketListen* pListen, const char* certname_pem, const char* prikeyname_pem, const char* password) : CSocketServer(pListen), CSSLSocket(m_sot, certname_pem, prikeyname_pem, password)
{
}

CSSLSocketServer::~CSSLSocketServer()
{
}

bool CSSLSocketServer::UseMethod()
{
	bool ret = false;
	meth = SSLv23_server_method();
	if (meth)
		ret = true;

	return ret;
}

int CSSLSocketServer::DoAccept()
{
	int ret = -2;
	ret = CSocketServer::DoAccept();
	if (-2 == ret)
	{
	}
	else if( -1 == ret)
	{
	}
	else if(0 == ret)
	{
	}
	else
	{
		bAccept = false;
		if (!Init())
		{
			//printf("SSL init failure %d", ret);
			ret = -1;
		}
		else
		{
			int Num = 8000;
			while(0 < Num)
			{
				bool bReadable = false;
				if (!IsReadable(&bReadable))
				{
					ret = -1;
					//printf("SSL'readable is failure\n");
					break;
				}
				else
				{
					if (!bReadable)
					{
					}
					else
					{
						ret =  SSL_accept(ToSSL(ssl));
						if (-1 == ret)
						{
							//printf("SSL accept failure %d\n", ret);
							break;
						}
						else if(0 == ret)
						{
							//printf("SSL accept failure %d\n", ret);
							break;
						}
						else
						{
							bAccept = true;
							break;
						}
					}
				}
				Num--;
			}
		}
	}

	return ret;
}

int CSSLSocketServer::Send(const char* pSendData, int len)
{
	int ret = 0;
	ret = SSLSend(pSendData, len);

	return ret;
}

int CSSLSocketServer::Recv(char* pRecvData, int len)
{
	int ret = -2;
	ret = SSLRecv(pRecvData, len);

	return ret;
}

CSSLSocketClient::CSSLSocketClient(const char* IP, int Port, const char* certname_pem, const char* prikeyname_pem, const char* password) : CSocketClient(IP, Port), CSSLSocket(m_sot, certname_pem, prikeyname_pem, password)
{
}

CSSLSocketClient::~CSSLSocketClient()
{
}

bool CSSLSocketClient::UseMethod()
{
	bool ret = false;
	meth = SSLv23_client_method();
	if (meth)
		ret = true;

	return ret;
}

int CSSLSocketClient::DoConnect(int to_second)
{
	int ret = -1;
	ret = CSocketClient::DoConnect(to_second);
	if (-1 != ret)
	{
		bConnect = false;
		if (!Init())
		{
			ret = -1;
		}
		else
		{
			int Num = 8000;
			while(Num)
			{
				bool bWrite = false;
				if (!CSocketClient::IsWritable(&bWrite))
				{
					//printf("socket connect is error\n");
					break;
				}
				if (!bWrite)
				{
				}
				else
				{
					ret = SSL_connect(ToSSL(ssl));
					if (1 != ret)
					{
						//printf("ssl connect is failure\n");
						break;
					}
					else
					{
						//printf("ssl connect is succeed\n");
						bConnect = true;
						break;
					}
				}
				Num--;
			}
		}
	}

	return ret;
}

int CSSLSocketClient::Send(const char* pSendData, int len)
{
	int ret = 0;
	ret = SSLSend(pSendData, len);

	return ret;
}

int CSSLSocketClient::Recv(char* pRecvData, int len)
{
	int ret = -2;
	ret = SSLRecv(pRecvData, len);

	return ret;
}
