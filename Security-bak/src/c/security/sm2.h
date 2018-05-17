//\file:sm2.h
//SM2 Algorithm
//2011-11-09
//comment:2011-11-10 sm2-sign-verify sm2-dh


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




#define  NID_X9_62_prime_field 406

#define ABORT do { \
				   fflush(stdout); \
				   fprintf(stderr, "%s:%d: ABORT\n", __FILE__, __LINE__); \
				   ERR_print_errors_fp(stderr); \
				   exit(1); \
			   } while (0);



static void BNPrintf(BIGNUM* bn)
{
	char *cptr=NULL;
	cptr=BN_bn2hex(bn);
	printf("%s\n",cptr);
	OPENSSL_free(cptr);
}

//Initialize the parameters for SM2_sign
EC_KEY * SM2_sign_init();


//SM2_sign_setup
int SM2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);



//SM2_sign_ex

int	SM2_sign_ex(const unsigned char *dgst, int dlen, unsigned char
	*sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

//SM2_sign
int	SM2_sign(const unsigned char *dgst, int dlen, unsigned char
		*sig, unsigned int *siglen, EC_KEY *eckey);

//SM2_verify
int SM2_verify(const unsigned char *dgst, int dgst_len,
		const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);




int	  CHN_SM2_INIT(const unsigned char *m, int m_len,
	unsigned char *uID, int u_len, unsigned char *dgst);

/*
 * Function CHN_SM2_sign to make a signature with the standard SM2 algorithm.
 * parameter m the input message (could be the generated random data)
 * parameter m_len the length of m
 * parameter uID the input user ID
 * parameter u_len length of uID
 * parameter signature the generated signature (in DER format)
 * parameter length of sig
 * return 1 on success or 0.
 */
int	  CHN_SM2_sign(const unsigned char *m, int m_len,
unsigned char *uID, int u_len, unsigned char *sig,
int *sig_len, unsigned char *pubkeyID, int *pubkeyID_len, EC_KEY *eckey);


int	  CHN_SM2_verify(const unsigned char *m, int m_len,
	unsigned char *uID, int u_len, unsigned char *sig, int sig_len, EC_KEY *eckey);

