/* cs_openssl_init.h -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#ifndef _CS_OPENSSL_INIT_
#define _CS_OPENSSL_INIT_

#include <stdio.h>
#include <stdlib.h>
#include <string>

class cs_openssl_init
{
public:
	cs_openssl_init(void);
	~cs_openssl_init(void);
public:
	static void all_free();
};

#endif
