/* Interface_CSocket.h -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com
 * welcome to use freely
 */

#ifndef _INTERFACE_CSOCKET_
#define _INTERFACE_CSOCKET_


/*
* #include <dlfcn.h>
* void *dlopen(const char *libname,int flag);//RTLD_LAZY/RTLD_NOW
* char *dlerror(void); 
* void *dlsym(void *handle,const char *symbol); 
*/

#ifdef __cplusplus
extern "C" {
#endif


void* InitCSSLEnviroment();
void ReleaseCSSLEnviroment(void* p);

void* InitCSocketListen(int Port, bool noneBlock=true);
bool DoListen(void* p, int c=5);
bool IsListen(void* p);
void ReleaseCSocketListen(void* p);

void* InitCSocketServer(void* pListen);
void ReleaseCSocketServer(void* p);
const struct sockaddr_in* ServerGetsockaddr_in(void* p);
int DoServerAccept(void* p);
bool IsServerAccept(void* p);
int ServerSend(void* p, const char* pSendData, int len);
int ServerRecv(void* p, char* pRecvData, int len);

void* InitCSocketClient(const char* IP, int Port);
void ReleaseCSocketClient(void* p);
int DoClientConnect(void* p, int to_second=8);
bool IsClientConnect(void* p);
int ClientSend(void* p, const char* pSendData, int len);
int ClientRecv(void* p, char* pRecvData, int len);

void* InitCSSLSocketServer(void* pListen, const char* certname_pem, const char* prikeyname_pem, const char* password=0);
void ReleaseCSSLSocketServer(void* p);
const struct sockaddr_in* SSLServerGetsockaddr_in(void* p);
int DoSSLServerAccept(void* p);
bool IsSSLServerAccept(void* p);
int SSLServerSend(void* p, const char* pSendData, int len);
int SSLServerRecv(void* p, char* pRecvData, int len);

void* InitCSSLSocketClient(const char* IP, int Port, const char* certname_pem = 0, const char* prikeyname_pem = 0, const char* password=0);
void ReleaseCSSLSocketClient(void* p);
int DoSSLClientConnect(void* p, int to_second=8);
bool IsSSLClientConnect(void* p);
int SSLClientSend(void* p, const char* pSendData, int len);
int SSLClientRecv(void* p, char* pRecvData, int len);


#ifdef __cplusplus
}
#endif 

#endif
