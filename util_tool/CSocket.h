/* CSocket.h -- internal utility state
 * Copyright (C++) forever zhangcl 791398105@qq.com
 * welcome to use freely
 */

#ifndef _CSOCKET_
#define _CSOCKET_


#include <pthread.h>  
#include <netinet/in.h>


class CSocket
{
protected:
	int m_sot;
	CSocket();
public:
	virtual ~CSocket();
public:
	int GetSocket();
	bool IsReadable(bool* pVal);
	bool IsWritable(bool* pVal);
	virtual int Send(const char* pSendData, int len);
	virtual int Recv(char* pRecvData, int len);
};

class CSocketListen : public CSocket
{
	int  m_port;
	bool m_noneBlock;
	bool bListen;
public:
	CSocketListen(int Port, bool noneBlock=true);
	virtual ~CSocketListen();
public:
	bool DoListen(int c=5);
	bool IsListen();
	int DoAccept(struct sockaddr_in* psa_cli);
};

class CSocketServer : public CSocket
{
	CSocketListen* m_pListen;
	struct sockaddr_in sa_cli;
protected:
	bool bAccept;
public:
	CSocketServer(CSocketListen* pListen);
	virtual ~CSocketServer();
public:
	const struct sockaddr_in* Getsockaddr_in();
	virtual int DoAccept();
	bool IsAccept();
};

class CSocketClient : public CSocket
{
	char m_ip[256];
	int  m_port;
protected:
	bool bConnect;
public:
	CSocketClient(const char* IP, int Port);
	virtual ~CSocketClient();
public:
	virtual int DoConnect(int to_second=8);
	bool IsConnect();
};

class CSSLEnviroment
{
public:
	CSSLEnviroment();
	~CSSLEnviroment();
};

class CSSLSocket
{
	int& m_refsot;
	char cert_pem_file[256];
	char prikey_pem_file[256];
	char m_password[256];
protected:
	void*       ctx;
	void*       ssl;
	const void* meth;
	bool bInit;
	CSSLSocket(int& refsot, const char* certname_pem, const char* prikeyname_pem, const char* password);
public:
	virtual ~CSSLSocket();
protected:
	virtual bool UseMethod();
	bool LoadFile(const char* certname_pem, const char* prikeyname_pem, const char* password);
	bool Init();
public:
	bool GetErrorMsg(char* pErrMsg, int* plErrMsg);
	int SSLSend(const char* pSendData, int len);
	int SSLRecv(char* pRecvData, int len);
};

class CSSLSocketServer : public CSocketServer, CSSLSocket
{
public:
	CSSLSocketServer(CSocketListen* pListen, const char* certname_pem, const char* prikeyname_pem, const char* password = NULL);
	virtual ~CSSLSocketServer();
protected:
	virtual bool UseMethod();
public:
	virtual int DoAccept();
	virtual int Send(const char* pSendData, int len);
	virtual int Recv(char* pRecvData, int len);
};

class CSSLSocketClient : public CSocketClient, CSSLSocket
{
public:
	CSSLSocketClient(const char* IP, int Port, const char* certname_pem = NULL, const char* prikeyname_pem = NULL, const char* password = NULL);
	virtual ~CSSLSocketClient();
protected:
	virtual bool UseMethod();
public:
	virtual int DoConnect(int to_second=8);
	virtual int Send(const char* pSendData, int len);
	virtual int Recv(char* pRecvData, int len);
};

#endif
