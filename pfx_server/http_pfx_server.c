/* http_pfx_server.c -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "CPFXServer.h"

/*
* export LD_LIBRARY_PATH=./
*/

#include <mcheck.h>
#define DEBUG

int main(int argc, char *argv[])
{
	const char* ssl = 0;
	bool bssl = false;
	const char* port = 0;
	const char* certfile_pem_name = 0;
	const char* prikeyfile_pem_name = 0;
	const char* password = 0;
	if (1>=argc)
	{
		printf("\n\n%s\n", "TIP(operator):");
		printf("%s\n", "parameter: bool ssl, char* port, char* certfile_pem, char* prikeyfile_pem, char* password");
		printf("%s\n", "example1: http_pfx_server.exe false 80200");
		printf("%s\n", "example2: http_pfx_server.exe  true 80201 127cert.pem 127key.pem");
		printf("%s\n", "example3: http_pfx_server.exe  true 80202 127cert.pem 127key.pem 12345678");
		return 1;
	}
	else if (3<=argc)
	{
		ssl = argv[1];
		if (!ssl || 0>=strlen(ssl))
		{
			printf("%s\n", "no assigning SSL, exiting now");
			return -1;
		}
		port = argv[2];
		if (!port || 0>=strlen(port))
		{
			printf("%s\n", "no assigning PORT, exiting now");
			return -1;
		}
		if (0==strcmp("true", ssl))
		{
			bssl = true;
			certfile_pem_name = argv[3];
			prikeyfile_pem_name = argv[4];
			if (!certfile_pem_name || 0>=strlen(certfile_pem_name) || !prikeyfile_pem_name || 0>=strlen(prikeyfile_pem_name))
			{
				printf("%s\n", "In SSL comu env, certfile_pem_name or prikeyfile_pem_name is unavailable, exiting now");
				return -1;
			}
			if (6==argc)
			{
				password = argv[5];
				if (!password || 0>=strlen(password))
				{
					printf("%s\n", "password is unavailable, exiting now");
					return -1;
				}
			}
		}
	}
	else
	{
		printf("%s\n", "params is too short, exiting now");
		return -1;
	}

	#ifdef DEBUG
		setenv("MALLOC_TRACE", "./debug_file.txt", 1);
        mtrace();
    #endif
	CPFXServer server(bssl, port, certfile_pem_name, prikeyfile_pem_name, password);
	server.main_loop();

	printf("%s\n", "\n\nnormal exit, now");

	return 0;
}
