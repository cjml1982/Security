// \file:sm2_envelop.c
//SM2 Algorithm
//2017-06-09
//depending:opnessl library


#include "sm2_envelope.h"
#include "sm3.h"


static int sm2_kdf(const unsigned char *share, size_t sharelen, size_t keylen, unsigned char *outkey)
{
	int ret = 0;

    sm3_context sm3var_ctx;
	unsigned char counter[4] = {0, 0, 0, 1};
	unsigned char dgst[M_MAX_MD_SIZE];
	unsigned int dgstlen;
	int rlen = (int)keylen;
	unsigned char * pp;

	pp = outkey;

	if (keylen > (size_t)32*255)
	{
		goto end;
	}

    while (rlen > 0)
	{

        sm3_starts(&sm3var_ctx);
        sm3_update(&sm3var_ctx, share, sharelen);
	    sm3_update(&sm3var_ctx, counter, 4);
        sm3_finish(&sm3var_ctx, dgst);
        dgstlen = 32;
		memcpy(pp, dgst, keylen>=dgstlen ? dgstlen:keylen);

		rlen -= dgstlen;
		pp += dgstlen;
		counter[3]++;
	}

	ret = 1;

end:
	return ret;
}




int CHN_SM2_public_encrypt( 
                       int  	type,                       
                       int  	flen,
		   const unsigned char *  	from,
		   unsigned char *  	to,
		   EC_KEY *eckey
	       )
{

    sm3_context sm3var_ctx;

    int kdfret = 0;
    int iret= -1;
	BN_CTX   *ctx = NULL;
    BIGNUM	 *k = NULL, *order = NULL, *X = NULL,*Y = NULL;
	EC_POINT *tmp_point=NULL;
	const EC_GROUP *group;
	const EC_POINT *pub_key;
    const EC_POINT *point = NULL;


    BIGNUM  *X2 = NULL,*Y2 = NULL;
    int X_blen = 0,Y_blen = 0;
    int X2_blen = 0,Y2_blen = 0, XY2_blen = 0, xor_blen = 0; 
    int c1_blen = 0;
    int i,offset;
    int keylen = flen;

    unsigned char  X_byte[M_ECCBYTE_MAXL];
    unsigned char  Y_byte[M_ECCBYTE_MAXL];

    unsigned char  X2_byte[M_ECCBYTE_MAXL];
    unsigned char  Y2_byte[M_ECCBYTE_MAXL];
    unsigned char  XY2_byte[2*M_ECCBYTE_MAXL];
    unsigned char  t_byte[M_KLEN_MAX+1];
    unsigned char  C1[2*M_ECCBYTE_MAXL+2];
    unsigned char  C2[M_KLEN_MAX+1];
    unsigned char  C3[M_HASHL_MAX+1];
    

    memset(X_byte,0,sizeof(X_byte));
    memset(Y_byte,0,sizeof(Y_byte));

    memset(X2_byte,0,sizeof(X2_byte));
    memset(Y2_byte,0,sizeof(Y2_byte));
    memset(XY2_byte,0,sizeof(XY2_byte));
    memset(t_byte,0,sizeof(t_byte));
    memset(C1,0,sizeof(C1));
    memset(C2,0,sizeof(C2));
    memset(C3,0,sizeof(C3));


    if ( flen > M_KLEN_MAX )
    {
        return 0;
    }
    keylen = flen;
    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL)
	{
		
		return 0;
	}

    if ( (pub_key = EC_KEY_get0_public_key(eckey)) == NULL )
	{
		
		return 0;
	}


	if ((ctx = BN_CTX_new()) == NULL)
	{
	
		return 0;
	}


	k     = BN_new();	
	order = BN_new();
	X     = BN_new();
	Y     = BN_new();
	X2    = BN_new();
	Y2    = BN_new();
	if (!k || !order || !X || !Y || !X2 || !Y2)
	{
		
		goto pub_err;
	}


	//if ((tmp_point = EC_GROUP_get0_generator(group)) == NULL)
	if ((tmp_point = EC_POINT_new(group)) == NULL)
	{
		
		goto pub_err;
	}
	
	if (!EC_GROUP_get_order(group, order, ctx))
	{
		
		goto pub_err;
	}


    do
	{
		/* get random k */	
		do
			if (!BN_rand_range(k, order))
			{
				
				goto pub_err;
			}
		while (BN_is_zero(k));

       
	

		/* compute r the x-coordinate of generator * k */
		if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx))
		{
			
			goto pub_err;
		}
		
	
		

		if (!EC_POINT_get_affine_coordinates_GFp(group,
			tmp_point, X, Y, ctx))
		{
			
			goto pub_err;
		}


	}
	while (0);

    //if((point=EC_GROUP_get0_generator(group)) == NULL)
    if ((point = EC_POINT_new(group)) == NULL)
    {
        
        goto pub_err;

    }
    if (!EC_POINT_mul(group, point, NULL, pub_key, k, ctx))
    {
        
        goto pub_err;

    }

	if (!EC_POINT_get_affine_coordinates_GFp(group,
		point, X2, Y2, ctx))
	{
		
		goto pub_err;
	}



    X_blen = BN_bn2bin(X, X_byte);
    Y_blen = BN_bn2bin(Y, Y_byte);  
    
    c1_blen = 0;
    C1[0] = M_PC;
    if ( X_blen <= M_ECC_LBYTE )
    {
        offset = M_ECC_LBYTE - X_blen; 
        memcpy(C1+1+offset,X_byte,X_blen);
        if ( Y_blen <= M_ECC_LBYTE ) 
        {
            offset = M_ECC_LBYTE - Y_blen; 
            memcpy(C1+1+M_ECC_LBYTE+offset,Y_byte,Y_blen);
            c1_blen = 2*M_ECC_LBYTE+1;
        }

    }
    
    X2_blen = BN_bn2bin(X2, X2_byte);
    Y2_blen = BN_bn2bin(Y2, Y2_byte);
    XY2_blen = X2_blen + Y2_blen;

    if (  X2_blen <= M_ECC_LBYTE )
    {
        XY2_blen = 0;
        offset = M_ECC_LBYTE - X2_blen; 
        memcpy(XY2_byte+offset,X2_byte,X2_blen);
        if (  Y2_blen <= M_ECC_LBYTE )
        {
            offset = M_ECC_LBYTE - Y2_blen; 
            memcpy(XY2_byte+M_ECC_LBYTE+offset,Y2_byte,Y2_blen);
            XY2_blen = 2 * M_ECC_LBYTE;
        }
    }

    
    kdfret = sm2_kdf(XY2_byte,XY2_blen,keylen,t_byte);
    if ( kdfret == 0 )
    {
        goto pub_err;
    }
    for(i=0; i < keylen; i++ )
    {
        C2[i] = from[i]^t_byte[i];   
    }

/*
    printf("inputhash:\n");
    for(i = 0; i < 2*M_ECC_LBYTE; i++ )
    {
        printf("%02X",XY2_byte[i]);
        if ( (i+1)%32 == 0)
            printf("\n");
    }
    printf("\n");
*/

	sm3_starts(&sm3var_ctx);
	//sm3_update(&sm3var_ctx, X2, X2_blen);
    sm3_update(&sm3var_ctx, XY2_byte, M_ECC_LBYTE);
	sm3_update(&sm3var_ctx, from, keylen);
	//sm3_update(&sm3var_ctx, Y2, Y2_blen);
    sm3_update(&sm3var_ctx, XY2_byte+M_ECC_LBYTE, M_ECC_LBYTE);

    sm3_finish(&sm3var_ctx, C3);
    if (( c1_blen > 0 ) && (XY2_blen > 0))
    {
        memcpy(to,C1,c1_blen);
        memcpy(to+c1_blen,C2,keylen);
        memcpy(to+c1_blen+keylen,C3,M_HASHL_MAX);
        iret = 0;
        iret = c1_blen+keylen+M_HASHL_MAX;

    }
pub_err:
	if (ctx != NULL) 
		BN_CTX_free(ctx);
	if (k != NULL)
		BN_free(k);
	if (order != NULL)
		BN_free(order);
	if (tmp_point != NULL) 
		EC_POINT_free(tmp_point);
	if (X != NULL )
		BN_clear_free(X);
	if (Y != NULL)
		BN_clear_free(Y);

	if (point != NULL)
		 EC_POINT_free(point);
	if (X2 != NULL )
		BN_clear_free(X2);
	if (Y2 != NULL)
		BN_clear_free(Y2);

    return(iret);


}






int CHN_SM2_private_decrypt( 
                        int  	type,
                        int  flen,
		   const unsigned char *  	from,
		   unsigned char *  	to,
		   EC_KEY *eckey
	       )
{
    int iret= -1;
    int kdfret = 0;

    sm3_context sm3var_ctx;
	BN_CTX   *ctx = NULL;
	EC_POINT *tmp_point=NULL;
	const EC_GROUP *group;
    const EC_POINT *point = NULL;
    const BIGNUM *priv_key = NULL;

    BIGNUM	*X = NULL,*Y = NULL;
    BIGNUM  *X2 = NULL,*Y2 = NULL;
    int X_blen = 0,Y_blen = 0;
    int X2_blen = 0,Y2_blen = 0, XY2_blen = 0, xor_blen = 0; 
    int c1_blen = 0;
    int i,offset;

    int keylen = flen;

    //unsigned char  X_byte[M_ECCBYTE_MAXL];
    //unsigned char  Y_byte[M_ECCBYTE_MAXL];

    unsigned char  X2_byte[M_ECCBYTE_MAXL];
    unsigned char  Y2_byte[M_ECCBYTE_MAXL];
    unsigned char  XY2_byte[2*M_ECCBYTE_MAXL];
    unsigned char  t_byte[M_KLEN_MAX+1];
    unsigned char  C1[2*M_ECCBYTE_MAXL+2];
    unsigned char  C2[M_KLEN_MAX+1];
    unsigned char  C3[M_HASHL_MAX+1];
    unsigned char * pbasem = NULL;

    //memset(X_byte,0,sizeof(X_byte));
    //memset(Y_byte,0,sizeof(Y_byte));

    memset(X2_byte,0,sizeof(X2_byte));
    memset(Y2_byte,0,sizeof(Y2_byte));
    memset(XY2_byte,0,sizeof(XY2_byte));
    memset(t_byte,0,sizeof(t_byte));
    memset(C1,0,sizeof(C1));
    memset(C2,0,sizeof(C2));
    memset(C3,0,sizeof(C3));


	X     = BN_new();
	Y     = BN_new();
	X2    = BN_new();
	Y2    = BN_new();
	if (!X || !Y || !X2 || !Y2)
	{
		
		goto priv_err;
	}
   
    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL)
	{
		return 0;
	}

	if ((ctx = BN_CTX_new()) == NULL)
	{
		return 0;
	}

    priv_key = EC_KEY_get0_private_key(eckey);
    if (group == NULL || priv_key == NULL )
	{
		goto priv_err;

	}

	if ((tmp_point = EC_POINT_new(group)) == NULL)
	{
		goto priv_err;
	}


    if ((point = EC_POINT_new(group)) == NULL)
    {
        goto priv_err;

    }

    if ( from[0] != M_PC )
    {
        goto priv_err;
    }

    Y_blen = X_blen = M_ECC_LBYTE;
    if (!BN_bin2bn(from+1,X_blen,X))
    {
        goto priv_err;
    }
    if (!BN_bin2bn(from+1+X_blen,Y_blen,Y))
    {
	    goto priv_err;
    }

    //if (!EC_POINT_set_compressed_coordinates_GFp(group, tmp_point, X, Y, ctx)) 
    if (!EC_POINT_set_affine_coordinates_GFp(group, tmp_point, X, Y, ctx)) 
    {
        goto priv_err;
    }

    if (!EC_POINT_is_on_curve(group, tmp_point, ctx))
    {
        goto priv_err;
    }


    if (!EC_POINT_mul(group, point, NULL, tmp_point, priv_key, ctx))
    {

        goto priv_err;

    }

	if (!EC_POINT_get_affine_coordinates_GFp(group,
		point, X2, Y2, ctx))
	{
		goto priv_err;
	}


    X2_blen = BN_bn2bin(X2, X2_byte);
    Y2_blen = BN_bn2bin(Y2, Y2_byte);
    XY2_blen = X2_blen + Y2_blen;

    if (  X2_blen <= M_ECC_LBYTE )
    {
        XY2_blen = 0;
        offset = M_ECC_LBYTE - X2_blen; 
        memcpy(XY2_byte+offset,X2_byte,X2_blen);
        if (  Y2_blen <= M_ECC_LBYTE )
        {
            offset = M_ECC_LBYTE - Y2_blen; 
            memcpy(XY2_byte+M_ECC_LBYTE+offset,Y2_byte,Y2_blen);
            XY2_blen = 2 * M_ECC_LBYTE;
        }
    }

    
    kdfret = sm2_kdf(XY2_byte,XY2_blen,keylen,t_byte);
    if ( kdfret == 0 )
    {
        goto priv_err;
    }

    c1_blen = 2*M_ECC_LBYTE+ 1;
    keylen = flen - (2*M_ECC_LBYTE+ 1 + M_HASHL_MAX);
    pbasem = from+(2*M_ECC_LBYTE+ 1);
    for(i=0; i < keylen; i++ )
    {
        C2[i] = pbasem[i]^t_byte[i];   
    }

/*
    printf("inputhash:\n");
    for(i = 0; i < 2*M_ECC_LBYTE; i++ )
    {
        printf("%02X",XY2_byte[i]);
        if ( (i+1)%32 == 0)
            printf("\n");
    }
    printf("\n");
*/

	sm3_starts(&sm3var_ctx);
	//sm3_update(&sm3var_ctx, X2, X2_blen);
    sm3_update(&sm3var_ctx, XY2_byte, M_ECC_LBYTE);
	sm3_update(&sm3var_ctx, C2, keylen);
	//sm3_update(&sm3var_ctx, Y2, Y2_blen);
    sm3_update(&sm3var_ctx, XY2_byte+M_ECC_LBYTE, M_ECC_LBYTE);

    sm3_finish(&sm3var_ctx, C3);
    if (XY2_blen > 0)
    {
        if ( memcmp(from+c1_blen+keylen,C3,M_HASHL_MAX) == 0 )
        {
             memcpy(to,C2,keylen);
             iret = keylen;
        }
        else
        {
             iret = 0;
        }

    }

priv_err:
	if (ctx != NULL) 
		BN_CTX_free(ctx);

	if (tmp_point != NULL) 
		EC_POINT_free(tmp_point);

	if (X != NULL )
		BN_clear_free(X);

	if (Y != NULL)
		BN_clear_free(Y);
	if (point != NULL)
		 EC_POINT_free(point);
	if (X2 != NULL )
		BN_clear_free(X2);
	if (Y2 != NULL)
		BN_clear_free(Y2);


    return(iret);

}

