/* cs_openssl_init.cpp -- internal utility state
 * Copyright (C) forever zhangcl 791398105@qq.com 
 * welcome to use freely
 */

#include "cs_openssl_init.h"

#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

cs_openssl_init::cs_openssl_init(void)
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
}


cs_openssl_init::~cs_openssl_init(void)
{
	CONF_modules_unload(1);        //for conf  
    EVP_cleanup();                 //For EVP  
    ENGINE_cleanup();              //for engine  
    CRYPTO_cleanup_all_ex_data();  //generic   
    // ERR_remove_state(0);           //for ERR  
    ERR_free_strings();            //for ERR  
}

void cs_openssl_init::all_free()
{
	CONF_modules_unload(1);        //for conf  
    EVP_cleanup();                 //For EVP  
    ENGINE_cleanup();              //for engine  
    CRYPTO_cleanup_all_ex_data();  //generic   
    // ERR_remove_state(0);           //for ERR  
    ERR_free_strings();            //for ERR  	
}
