//\file:sm2_envelop.h
//SM2 Algorithm
//2017-06-09
//comment:2017-06-09 


#include <stdio.h>
#include <time.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/engine.h>


#ifndef ENVELOP_SM2_H
#define ENVELOP_SM2_H


#ifdef __cplusplus
extern "C" {
#endif


#define  M_ECCBYTE_MAXL (512/8)
#define  M_KLEN_MAX  (128)   //byte
#define  M_HASHL_MAX (256/8)
#define  M_PC  (0x04)
#define  M_ECC_LBYTE (256/8)
#define  M_MAX_MD_SIZE  (M_HASHL_MAX+6)


extern int CHN_SM2_public_encrypt( 
                       int  	type,                       
                       int  	flen,
		   const unsigned char *  	from,
		   unsigned char *  	to,
		   EC_KEY *eckey
	       );


extern int CHN_SM2_private_decrypt( 
                        int  	type,
                        int  flen,
		   const unsigned char *  	from,
		   unsigned char *  	to,
		   EC_KEY *eckey
	       );


#ifdef __cplusplus
}
#endif

#endif /* sm2_envelop.h */
