/*---------------------------------------------------------------------------
//
//	Copyright(C) SMIT Corporation, 2011-2020.
//
//  File	:	interface_cryfun.h
//	Purpose	:
//	History :
//				2012-03-06 created by Bitter Chen
//				2017-04-13 modified by Bitter Chen
//
---------------------------------------------------------------------------*/
#ifndef INTERFACE_CRYPFUN_H
#define INTERFACE_CRYPFUN_H

#ifdef __cplusplus
extern "C"{
#endif


typedef unsigned int SMITC_UINT;
typedef SMITC_UINT SMITC_RV;


typedef SMITC_UINT  T_ndn_Error;
typedef unsigned char uint8_t;
//typedef unsigned int size_t;  //standard


SMITC_RV  SM_open_cryptodev(char *pdev);
SMITC_RV  SM_close_cryptodev(void);


char *  SM_get_version_cryptodev(void);



#define M_HALG_MODESHA256    (1)
#define M_HALG_MODESHA1      (2)

#define M_HALG_RESLUTL_SHA1     (20)
#define M_HALG_RESLUTL_SHA256   (32)
#define M_HALG_RESLUTL_MAXLEN    M_HALG_RESLUTL_SHA256


#define M_SMITCR_OK           (0)
#define M_SMITCR_EINPUTPARA   (0x8001)
#define M_SMITCR_ENOTOPENDEV  (0x8002)



#define M_SMITCR_WREOPEN      (0x9001)
#define M_RSA_PRVSING_NID_TYPE_UNDEF           (0xA004) 
#define M_RSA_PRVSING_NID_LEN_ERROR            (0xA005) 
#define M_RSA_PRVSING_CHGKEYTYPE               (0xA006) 
#define M_RSA_PRVSING_ADDPADDING_ERROR         (0xA007) 
#define M_RSA_PRVSING_UNKNOWN_PADDING          (0xA008) 
#define M_RSA_PRVSING_RUN_ALG_ERR              (0xA009) 


#define M_RSA_PUBVERI_NID_TYPE_UNDEF           (0xA104) 
#define M_RSA_PUBVERI_NID_LEN_ERROR            (0xA105) 
#define M_RSA_PUBVERI_CHGKEYTYPE               (0xA106) 
#define M_RSA_PUBVERI_CHECKPADDING_ERROR       (0xA107) 
#define M_RSA_PUBVERI_UNKNOWN_PADDING          (0xA108) 
#define M_RSA_PUBVERI_RUN_ALG_ERR              (0xA109) 
#define M_RSA_PUBVERI_NID_HEARDTAG_ERROR       (0xA10A) 
#define M_RSA_PUBVERI_NID_DIGEST_ERROR         (0xA10B)

#define M_RSA_PUBENC_UNKNOWN_PADDING           (0xA204) 
#define M_RSA_PUBENC_RUN_ALG_ERR               (0xA205) 
#define M_RSA_PUBENC_CHGKEYTYPE                (0xA206) 
#define M_RSA_PUBENC_ADDPADDING_ERROR          (0xA207) 


#define M_RSA_PRVDEC_PADDING_CHECK_FAILED      (0xA304) 
#define M_RSA_PRVDEC_RUN_ALG_ERR               (0xA305) 
#define M_RSA_PRVDEC_CHGKEYTYPE                (0xA306) 
#define M_RSA_PRVDEC_UNKNOWN_PADDING           (0xA307) 



SMITC_RV  SM_hash_alg(unsigned int uni_sel_alg, unsigned char *i_pdata, unsigned long  i_udatalen,
		   						unsigned char *o_pdata,unsigned long * o_dlen);


#define M_SALG_MODE_AES_ENC_ECB     (0)
#define M_SALG_MODE_AES_DEC_ECB     (1)
#define M_SALG_MODE_DES_ENC_ECB     (2)
#define M_SALG_MODE_DES_DEC_ECB     (3)
#define M_SALG_MODE_TDES_ENC_ECB    (4)
#define M_SALG_MODE_TDES_DEC_ECB    (5)

#define M_SALG_MODE_AES_ENC_CBC     (6)
#define M_SALG_MODE_AES_DEC_CBC     (7)
#define M_SALG_MODE_DES_ENC_CBC     (8)
#define M_SALG_MODE_DES_DEC_CBC     (9)
#define M_SALG_MODE_TDES_ENC_CBC    (10)
#define M_SALG_MODE_TDES_DEC_CBC    (11)


SMITC_RV  SM_symmetric_alg(unsigned int uni_sel_alg,unsigned char *i_pkey, unsigned long  i_ukeylen,
										unsigned char *i_pvector, unsigned long  i_vectorlen,
											unsigned char *i_pdata, unsigned long  i_udatalen,
		   										unsigned char *o_pdata, size_t  *o_udatalen);


#define M_ECC_MODE_SIGN      (0)
#define M_ECC_MODE_VERFIY    (1)

#define M_ECCP_LEN           (256/8)

SMITC_RV  SM_asymmetric_ecc(unsigned int uni_sel_alg,unsigned char * i_phashe, unsigned long  i_hashelen,
												unsigned char *io_r, unsigned long  io_rlen,
		   										unsigned char *io_s, unsigned long  io_slen);





T_ndn_Error
ndn_AesAlgorithm_encrypt128Cbc_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *plainData,
   size_t plainDataLength, uint8_t *encryptedData, size_t *encryptedDataLength);


T_ndn_Error
ndn_AesAlgorithm_decrypt128Cbc_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *encryptedData,
   size_t encryptedDataLength, uint8_t *plainData, size_t *plainDataLength);


T_ndn_Error
ndn_AesAlgorithm_encrypt128Ecb_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *plainData,
   size_t plainDataLength, uint8_t *encryptedData, size_t *encryptedDataLength);


T_ndn_Error
ndn_AesAlgorithm_decrypt128Ecb_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *encryptedData,
   size_t encryptedDataLength, uint8_t *plainData, size_t *plainDataLength);


T_ndn_Error
ndn_digestSha256_hardware(const uint8_t *data, size_t dataLength, uint8_t *digest);


#ifndef RSA_PKCS1_PADDING
#define RSA_PKCS1_PADDING	1
#endif
#ifndef RSA_PKCS1_OAEP_PADDING
#define RSA_PKCS1_OAEP_PADDING	4
#endif
#ifndef NID_sha256
#define NID_sha256		672
#endif


#define SMRSA_MAX_BITS    2048
#define SMRSA_MAX_LEN     ((SMRSA_MAX_BITS + 7) / 8)

typedef struct SMRSA_Key_st
{
unsigned int  bits;
unsigned int  bytes;
unsigned char m[SMRSA_MAX_LEN];
unsigned char r[SMRSA_MAX_LEN];
unsigned char e[SMRSA_MAX_LEN];
unsigned char d[SMRSA_MAX_LEN];

} SMRSA_Key;

#define SMECC_MAX_BITS			512 
#define SMECC_MAX_LEN			((SMECC_MAX_BITS+7) / 8)

typedef struct SMECC_Key_st
{
	unsigned int  bits;
	unsigned char x[SMECC_MAX_LEN]; 
	unsigned char y[SMECC_MAX_LEN]; 
    unsigned char D[SMECC_MAX_LEN];

} SMECC_Key;



extern int RSA_public_encrypt_hardware( 	int  	flen,
		   const unsigned char *  	from,
		   unsigned char *  	to,
		   SMRSA_Key  *  	prsa_pbl,
		   int  	padding, 
           SMITC_RV *pRetSt
	       );


extern int RSA_verify_hardware 	( 	int  	type,
		   const unsigned char *  	m,
		   unsigned int  	m_length,
		   const unsigned char *  	sigbuf,
		   unsigned int  	siglen,
		   SMRSA_Key  *  	prsa_pbl,
           SMITC_RV *pRetSt
        );



extern int RSA_private_decrypt_hardware( int  flen,
		   const unsigned char *  	from,
		   unsigned char *  	to,
		   SMRSA_Key  *  	prsa_prv,
		   int  	padding,
           SMITC_RV *pRetSt
	       ); 	




extern int RSA_sign_hardware( 	int  	type,
		   const unsigned char *  	m,
		   unsigned int  	m_length,
		   unsigned char *  	sigret,
		   unsigned int *  	siglen,
		   SMRSA_Key  *  	prsa_prv,
           SMITC_RV *pRetSt
	       );




#ifdef __cplusplus
}
#endif

#endif /* interface_cryfun.h */
