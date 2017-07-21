#include <stdio.h>
#include <stdlib.h>
#include "app_util.h"
#include "Interface_CSocket.h"

#include <mcheck.h>
#define DEBUG
// ./test.exe
//  mtrace test.exe debug_file.txt

int main()
{
	/*CMemPoint<char, size_t> mP = (char*)malloc(100);
	memset(mP, 0, 100);
	memcpy(mP+(size_t)3, "1", 1);
	void* p = (void*)mP;
	
	CMemBlock<char> mem;
	mem.Resize(100);
	mem.Zero();
	memcpy(mem, "123", 4);
	void* cp = mem;
	printf("%s\n", (char*)mem);

	char* buf = (char*)malloc(128);
	mem.SetMemFixed((const char*)buf, 128);
	mem.Zero();
	memcpy(mem, "123", 4);
	printf("%s\n", (char*)mem);
	mem.Clear();
	free(buf);

	CMemBlock<unsigned char> base64 = CBase64::Encode((unsigned char*)"123", 4);
	CMemBlock<unsigned char> unbase64 = CBase64::Decode(base64, (long)base64.GetSize());
	printf("%s\n", (char*)(unsigned char*)unbase64);

	void* Handle = InitCSSLEnviroment();
	if (Handle)
	{
		ReleaseCSSLEnviroment(Handle);
	}*/

	//
	#ifdef DEBUG
		setenv("MALLOC_TRACE", "./debug_file.txt", 1);
        mtrace();
    #endif


	void* pListen = InitCSocketListen(8020);
	if (DoListen(pListen))
	{
		printf("listen is working\n");
		void* pServer = InitCSocketServer(pListen);
		if (pServer)
		{
			printf("server is working\n");
			while(1)
			{
				DoServerAccept(pServer);
				if (IsServerAccept(pServer))
				{
					printf("connect is established\n");
					CMemBlock<char, int> buf(1024);
					while(1)
					{
						int len = ServerRecv(pServer, buf, buf.GetSize());
						if (0<len)
						{
							ServerSend(pServer, buf, len);
							break;
						} 
					}

					ReleaseCSocketServer(pServer);
					printf("connect is closed\n");
					printf("server is quit\n");
					break;
				}
			}
		}
		ReleaseCSocketListen(pListen);
		printf("listen is quit");
	}

	return 0;
}
