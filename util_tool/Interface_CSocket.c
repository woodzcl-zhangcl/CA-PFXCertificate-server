/* Interface_CSocket.cpp -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com
 * welcome to use freely
 */

#include "Interface_CSocket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "CSocket.h"



void* InitCSSLEnviroment()
{
	return new CSSLEnviroment();
}

void ReleaseCSSLEnviroment(void* p)
{
	delete (CSSLEnviroment*)p;
}

void* InitCSocketListen(int Port, bool noneBlock)
{
	return new CSocketListen(Port, noneBlock);
}

bool DoListen(void* p, int c)
{
	return ((CSocketListen*)p)->DoListen(c);
}
bool IsListen(void* p)
{
	return ((CSocketListen*)p)->IsListen();
}

void ReleaseCSocketListen(void* p)
{
	delete (CSocketListen*)p;
}

void* InitCSocketServer(void* pListen)
{
	return new CSocketServer((CSocketListen*)pListen);
}

void ReleaseCSocketServer(void* p)
{
	delete (CSocketServer*)p;
}

const struct sockaddr_in* ServerGetsockaddr_in(void* p)
{
	return ((CSocketServer*)p)->Getsockaddr_in();
}

int DoServerAccept(void* p)
{
	return ((CSocketServer*)p)->DoAccept();
}

bool IsServerAccept(void* p)
{
	return ((CSocketServer*)p)->IsAccept();
}

int ServerSend(void* p, const char* pSendData, int len)
{
	return ((CSocketServer*)p)->Send(pSendData, len);
}

int ServerRecv(void* p, char* pRecvData, int len)
{
	return ((CSocketServer*)p)->Recv(pRecvData, len);
}

void* InitCSocketClient(const char* IP, int Port)
{
	return new CSocketClient(IP, Port);
}

void ReleaseCSocketClient(void* p)
{
	delete (CSocketClient*)p;
}

int DoClientConnect(void* p, int to_second)
{
	return ((CSocketClient*)p)->DoConnect(to_second);
}

bool IsClientConnect(void* p)
{
	return ((CSocketClient*)p)->IsConnect();
}

int ClientSend(void* p, const char* pSendData, int len)
{
	return ((CSocketClient*)p)->Send(pSendData, len);
}

int ClientRecv(void* p, char* pRecvData, int len)
{
	return ((CSocketClient*)p)->Recv(pRecvData, len);
}

void* InitCSSLSocketServer(void* pListen, const char* certname_pem, const char* prikeyname_pem, const char* password)
{
	return new CSSLSocketServer((CSocketListen*)pListen, certname_pem, prikeyname_pem, password);
}

void ReleaseCSSLSocketServer(void* p)
{
	delete (CSSLSocketServer*)p;
}

const struct sockaddr_in* SSLServerGetsockaddr_in(void* p)
{
	return ((CSSLSocketServer*)p)->Getsockaddr_in();
}

int DoSSLServerAccept(void* p)
{
	return ((CSSLSocketServer*)p)->DoAccept();
}

bool IsSSLServerAccept(void* p)
{
	return ((CSSLSocketServer*)p)->IsAccept();
}

int SSLServerSend(void* p, const char* pSendData, int len)
{
	return ((CSSLSocketServer*)p)->Send(pSendData, len);
}

int SSLServerRecv(void* p, char* pRecvData, int len)
{
	return ((CSSLSocketServer*)p)->Recv(pRecvData, len);
}

void* InitCSSLSocketClient(const char* IP, int Port, const char* certname_pem, const char* prikeyname_pem, const char* password)
{
	return new CSSLSocketClient(IP, Port, certname_pem, prikeyname_pem, password);
}

void ReleaseCSSLSocketClient(void* p)
{
	delete (CSSLSocketClient*)p;
}

int DoSSLClientConnect(void* p, int to_second)
{
	return ((CSSLSocketClient*)p)->DoConnect(to_second);
}

bool IsSSLClientConnect(void* p)
{
	return ((CSSLSocketClient*)p)->IsConnect();
}

int SSLClientSend(void* p, const char* pSendData, int len)
{
	return ((CSSLSocketClient*)p)->Send(pSendData, len);
}

int SSLClientRecv(void* p, char* pRecvData, int len)
{
	return ((CSSLSocketClient*)p)->Recv(pRecvData, len);
}
