// \file:sm2.c
//SM2 Algorithm
//2011-11-10
//depending:opnessl library



#include "sm2.h"
#include "sm3.h"



//#define  DEBUG_PRINT


time_t start,end;

static	unsigned char *c_a = (unsigned char *)"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
static	unsigned char *c_b = (unsigned char *)"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
static	unsigned char *c_x = (unsigned char *)"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
static	unsigned char *c_y = (unsigned char *)"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
static	unsigned char *c_xa = (unsigned char *)"78b431066cc393707f8b9be1b1285cb93456861545df527d74b6461beabe10d6";
static	unsigned char *c_ya = (unsigned char *)"d66f835edc2036d1c71a2e575a17ad0f75f1d34fb726dd5699027f8d1df05bff";
static	unsigned char *c_p = (unsigned char *)"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
static	unsigned char *c_z = (unsigned char *)"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
static  unsigned char *c_da = (unsigned char *)"761a5da643a910efa96533cd7f030efaffe587a285e341cce1c8dcd29e289025";

	

EC_KEY * SM2_sign_init()
{
	

	BN_CTX *ctx = NULL;
	EC_GROUP *group;
	EC_POINT *P/*, *Q, *R*/;
	EC_KEY *eckey_tmp;


//	EC_KEY *eckey = NULL;		//to store public and private key, and group parameters
	
	BIGNUM *p, *a, *b;
	BIGNUM *x, *y, *z;
	BIGNUM *x_a, *y_a, *d_a;

	p = BN_new();
	a = BN_new();
	b = BN_new();
	x = BN_new();
	y = BN_new();
	z = BN_new();
	x_a = BN_new();
	y_a = BN_new();
	d_a = BN_new();
	
	if (!p || !a || !b || !x || !y || !z || !x_a || !y_a || !d_a) 
		{
		fprintf(stdout, " failed\n");
		ABORT;
		}
	//translate the hex mode vector to struct BIGNUM mode
	if (!BN_hex2bn(&p, c_p)) ABORT;
	if (!BN_hex2bn(&a, c_a)) ABORT;
	if (!BN_hex2bn(&b, c_b)) ABORT;
	if (!BN_hex2bn(&x, c_x)) ABORT;
	if (!BN_hex2bn(&y, c_y)) ABORT;
	if (!BN_hex2bn(&z, c_z)) ABORT;
	if (!BN_hex2bn(&x_a, c_xa)) ABORT;
	if (!BN_hex2bn(&y_a, c_ya)) ABORT;
	if (!BN_hex2bn(&d_a, c_da)) ABORT;

	ctx = BN_CTX_new();
	
	if (!ctx)
		{
		fprintf(stdout, " failed\n");
		ABORT;
		}

/*
	if (eckey == NULL || *eckey == NULL)
		{
			if ((eckey_tmp = EC_KEY_new()) == NULL)
				{
					fprintf(stdout, " failed\n");
					ABORT;
				}
		}
	else
		eckey_tmp = eckey;
*/
	if ((eckey_tmp = EC_KEY_new()) == NULL)
				{
					fprintf(stdout, " failed\n");
					ABORT;
				}

	//generate a group for ECC with given parameters	
	group = EC_GROUP_new(EC_GFp_mont_method()); /* applications should use EC_GROUP_new_curve_GFp
 	                                             * so that the library gets to choose the EC_METHOD */
	if (!group)
		{
		fprintf(stdout, " failed\n");
		ABORT;
		}
/*	
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
		{
		fprintf(stdout, " failed\n");
		ABORT;
		}
*/

	if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) ABORT;

	P = EC_POINT_new(group);

	if (!P) 
		{
		fprintf(stdout, " failed\n");
		ABORT;
		}

	if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx)) ABORT;

//	if (!EC_POINT_is_on_curve(group, P, ctx)) fprintf(stdout, " failed\n");	
	if (!EC_GROUP_set_generator(group, P, z, BN_value_one())) ABORT;
//	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) fprintf(stdout, " failed\n");

	/* G_y value taken from the standard: */
//	if (!BN_hex2bn(&tmpy, "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2")) fprintf(stdout, " failed\n");
//	if (0 != BN_cmp(y, tmpy)) fprintf(stdout, " failed\n");
	


	if (!EC_GROUP_precompute_mult(group, ctx)) fprintf(stdout, " failed\n");
	



	//set ECC parameters, priv_key, pub_key, and group
	if (EC_KEY_set_group(eckey_tmp, group) == 0)
	{
		fprintf(stdout," failed\n");
		ABORT;
//		goto builtin_err;
	}


	/* create key */

#ifdef DEBUG_PRINT
	start=clock();
#endif
/*
	if (!EC_KEY_generate_key(eckey))
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}

*/	
	
	//if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x_a, y_a, ctx)) ABORT;  //bug20170614
    if (!EC_POINT_set_affine_coordinates_GFp(group, P, x_a, y_a, ctx)) ABORT; 
//	if (!EC_POINT_is_on_curve(group, P, ctx)) ABORT;

	if(!EC_KEY_set_private_key(eckey_tmp, d_a)) ABORT;
	if(!EC_KEY_set_public_key(eckey_tmp, P)) ABORT;

#ifdef DEBUG_PRINT
	end=clock();
	printf("\nOperation EC_KEY_generate_key took time: %lfs\n",((double)(end-start))/CLOCKS_PER_SEC); 
#endif
	/* check key */

/*	
	if (!EC_KEY_check_key(eckey))
	{
		fprintf(stdout," failed\n");
		ABORT;
//		goto builtin_err;
	}
*/


	
builtin_err:

	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(z);
	BN_free(x_a);
	BN_free(y_a);
	BN_free(d_a);
	EC_POINT_free(P);
//	EC_GROUP_free(group);
	BN_CTX_free(ctx);


	return eckey_tmp;	
	
}


int sm2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kp, BIGNUM **rp)
{
	BN_CTX   *ctx = NULL;
	BIGNUM	 *k = NULL, *r = NULL, *order = NULL, *X = NULL;
	EC_POINT *tmp_point=NULL;
	const EC_GROUP *group;
	int 	 ret = 0;

	if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL)
	{
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (ctx_in == NULL) 
	{
		if ((ctx = BN_CTX_new()) == NULL)
		{
			ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_MALLOC_FAILURE);
			return 0;
		}
	}
	else
		ctx = ctx_in;

	k     = BN_new();	/* this value is later returned in *kp */
	r     = BN_new();	/* this value is later returned in *rp */
	order = BN_new();
	X     = BN_new();
	if (!k || !r || !order || !X)
	{
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if ((tmp_point = EC_GROUP_get0_generator(group)) == NULL)
//	if ((tmp_point = EC_POINT_new(group)) == NULL)

	{
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
		goto err;
	}
	
	if (!EC_GROUP_get_order(group, order, ctx))
	{
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
		goto err;
	}
	
	do
	{
		/* get random k */	
		do
			if (!BN_rand_range(k, order))
			{
				ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED);	
				goto err;
			}
		while (BN_is_zero(k));

#ifdef DEBUG_PRINT
		start = clock();
#endif

		/* compute r the x-coordinate of generator * k */
		if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx))
		{
			ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
			goto err;
		}

#ifdef DEBUG_PRINT
		end = clock();
		printf("\nOperation EC_POINT_mul took time: %lfs\n",((double)(end-start))/CLOCKS_PER_SEC);
#endif
		
		if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
		{
			if (!EC_POINT_get_affine_coordinates_GFp(group,
				tmp_point, X, NULL, ctx))
			{
				ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_EC_LIB);
				goto err;
			}
		}
		else /* NID_X9_62_characteristic_two_field */
		{
			if (!EC_POINT_get_affine_coordinates_GF2m(group,
				tmp_point, X, NULL, ctx))
			{
				ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_EC_LIB);
				goto err;
			}
		}
		if (!BN_nnmod(r, X, order, ctx))
		{
			ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
			goto err;
		}
	}
	while (BN_is_zero(r));

	/* compute the inverse of k */
// 	if (!BN_mod_inverse(k, k, order, ctx))
// 	{
// 		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
// 		goto err;	
// 	}
	/* clear old values if necessary */
	if (*rp != NULL)
		BN_clear_free(*rp);
	if (*kp != NULL) 
		BN_clear_free(*kp);
	/* save the pre-computed values  */
	*rp = r;
	*kp = k;
	ret = 1;
err:

	if (!ret)
	{
		if (k != NULL) BN_clear_free(k);
		if (r != NULL) BN_clear_free(r);
	}
	if (ctx_in == NULL) 
		BN_CTX_free(ctx);
	if (order != NULL)
		BN_free(order);
	if (tmp_point != NULL) 
		EC_POINT_free(tmp_point);
	if (X)
		BN_clear_free(X);

	return(ret);
}



 ECDSA_SIG *sm2_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *in_k, const BIGNUM *in_r, EC_KEY *eckey)
{
	int     ok = 0, i;
	BIGNUM *k=NULL, *s, *m=NULL,*tmp=NULL,*order=NULL;
	const BIGNUM *ck;
	BN_CTX     *ctx = NULL;
	const EC_GROUP   *group;
	ECDSA_SIG  *ret;
	//ECDSA_DATA *ecdsa;
	const BIGNUM *priv_key;
    BIGNUM *r,*x=NULL,*a=NULL;	//new added
	//ecdsa    = ecdsa_check(eckey);

	group    = EC_KEY_get0_group(eckey);
	priv_key = EC_KEY_get0_private_key(eckey);

#ifdef DEBUG_PRINT
	printf("\npriv_key of ECC:\n");
	BNPrintf(priv_key);
	printf("\n");
#endif
    

	if (group == NULL || priv_key == NULL /*|| ecdsa == NULL*/)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
		ABORT;
	}

	ret = ECDSA_SIG_new();
	if (!ret)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
		ABORT;
	}
	s = ret->s;
	r = ret->r;

	if ((ctx = BN_CTX_new()) == NULL || (order = BN_new()) == NULL ||
		(tmp = BN_new()) == NULL || (m = BN_new()) == NULL || 
		(x = BN_new()) == NULL || (a = BN_new()) == NULL)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	
	if (!EC_GROUP_get_order(group, order, ctx))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
		goto err;
	}

	i = BN_num_bits(order);
	
	/* Need to truncate digest if it is too long: first truncate whole
	 * bytes.
	 */
	if (8 * dgst_len > i)
		dgst_len = (i + 7)/8;
	if (!BN_bin2bn(dgst, dgst_len, m))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}
	/* If still too long truncate remaining bits with a shift */
	if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7)))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}

	do
	{
		if (in_k == NULL || in_r == NULL)
		{
			if (!sm2_sign_setup(eckey, ctx, &k, &x))
			{
				ECDSAerr(ECDSA_F_ECDSA_DO_SIGN,ERR_R_ECDSA_LIB);
				goto err;
			}
			ck = k;
		}
		else
		{
			ck  = in_k;
			if (BN_copy(x, in_r) == NULL)
			{
				ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
				goto err;
			}
		}
		
		if (BN_ucmp(m, order) >= 0)
			{
			BN_nnmod(m, m, order, ctx);
			}


		//r=(e+x1) mod n
		if (!BN_mod_add_quick(r, m, x, order))
		{
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}

// 		fprintf(stdout,"\n");

		if(BN_is_zero(r) )
			continue;

		BN_add(tmp,r,ck);
		if(BN_ucmp(tmp,order) == 0)
			continue;
				
		
		if (!BN_mod_mul(tmp, priv_key, r, order, ctx))
		{
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}

		
		if (!BN_mod_sub_quick(s, ck, tmp, order))
		{
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		BN_one(a);
		//BN_set_word((a),1);

		if (!BN_mod_add_quick(tmp, priv_key, a, order))
		{
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		/* compute the inverse of 1+dA */
		if (!BN_mod_inverse(tmp, tmp, order, ctx))
		{
			ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
			goto err;	
		}
// 		BNPrintf(tmp);
// 		fprintf(stdout,"\n");

		if (!BN_mod_mul(s, s, tmp, order, ctx))
		{
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
			
		
		if (BN_is_zero(s))
		{
			/* if k and r have been supplied by the caller
			 * don't to generate new k and r values */
			if (in_k != NULL && in_r != NULL)
			{
				ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ECDSA_R_NEED_NEW_SETUP_VALUES);
				goto err;
			}
		}
		else
			/* s != 0 => we have a valid signature */
			break;
	}
	while (1);

#ifdef DEBUG_PRINT
	printf("\nAfter Operation sign, info of output signature:\n");
	printf("r:\n");
	BNPrintf(r);
	printf("s:\n");
	BNPrintf(s);
	printf("\n");
#endif

	ok = 1;
err:

	if (!ok)
	{
		ECDSA_SIG_free(ret);
		ret = NULL;
	}
	if (ctx)
		BN_CTX_free(ctx);
	if (m)
		BN_clear_free(m);
	if (tmp)
		BN_clear_free(tmp);
	if (order)
		BN_free(order);
	if (k)
		BN_clear_free(k);
	if (x)
		BN_clear_free(x);
	if (a)
		BN_clear_free(a);

	return ret;
}


 int sm2_do_verify(const unsigned char *dgst, int dgst_len,
		 const ECDSA_SIG *sig, EC_KEY *eckey)
 {
	 int ret = 0, i;
	 BN_CTX   *ctx;
	 BIGNUM   *order, *R,  *m, *X,*t;
	 EC_POINT *point = NULL;
	 const EC_GROUP *group;
	 const EC_POINT *pub_key;
 
	 /* check input values */
	 if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
		 (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL)
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_MISSING_PARAMETERS);
		 return 0;
	 }
 
	 ctx = BN_CTX_new();
	 if (!ctx)
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		 return 0;
	 }
	 BN_CTX_start(ctx);
	 order = BN_CTX_get(ctx);	 
	 R	  = BN_CTX_get(ctx);
	 t	  = BN_CTX_get(ctx);
	 m	   = BN_CTX_get(ctx);
	 X	   = BN_CTX_get(ctx);
	 if (!X)
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		 goto err;
	 }
	 
	 if (!EC_GROUP_get_order(group, order, ctx))
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
		 goto err;
	 }
 
	 if (BN_is_zero(sig->r) 		 || BN_is_negative(sig->r) || 
		 BN_ucmp(sig->r, order) >= 0 || BN_is_zero(sig->s)	||
		 BN_is_negative(sig->s)  || BN_ucmp(sig->s, order) >= 0)
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_BAD_SIGNATURE);
		 ret = 0;	 /* signature is invalid */
		 goto err;
	 }
 
	 //t =(r+s) mod n
	 if (!BN_mod_add_quick(t, sig->s, sig->r,order))
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		 goto err;
	 }
	 if (BN_is_zero(t))
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_BAD_SIGNATURE);
		 ret = 0;	 /* signature is invalid */
		 goto err;
	 }
	 
	 //point = s*G+t*PA
 //  if ((point = EC_POINT_new(group)) == NULL)
	 if((point=EC_GROUP_get0_generator(group)) == NULL)
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		 goto err;
	 }
	 if (!EC_POINT_mul(group, point, sig->s, pub_key, t, ctx))
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
		 goto err;
	 }
	 if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
	 {
		 if (!EC_POINT_get_affine_coordinates_GFp(group,
			 point, X, NULL, ctx))
		 {
			 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
			 goto err;
		 }
	 }
	 else /* NID_X9_62_characteristic_two_field */
	 {
		 if (!EC_POINT_get_affine_coordinates_GF2m(group,
			 point, X, NULL, ctx))
		 {
			 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
			 goto err;
		 }
	 }
	 
	 
	 i = BN_num_bits(order);
	 
	 /* Need to truncate digest if it is too long: first truncate whole
	  * bytes.
	  */
	 if (8 * dgst_len > i)
		 dgst_len = (i + 7)/8;
	 if (!BN_bin2bn(dgst, dgst_len, m))
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		 goto err;
	 }
	 /* If still too long truncate remaining bits with a shift */
	 if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7)))
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		 goto err;
	 }
 
 
	 if (BN_ucmp(m, order) >= 0)
			 {
			 BN_nnmod(m, m, order, ctx);
			 }
 
	 /* R = m + X mod order */
	 if (!BN_mod_add_quick(R, m, X, order))
	 {
		 ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		 goto err;
	 }
 
#ifdef DEBUG_PRINT
	 printf("\nAfter operation verify");
	 printf("\nR = ");
	 BNPrintf(R);
	 printf("sig->r = ");
	 BNPrintf(sig->r);
	 printf("\n");
#endif

	 /*  if the signature is correct R is equal to sig->r */
	 ret = (BN_ucmp(R, sig->r) == 0);
 err:
	 BN_CTX_end(ctx);
	 BN_CTX_free(ctx);
	 if (point)
		 EC_POINT_free(point);
	 return ret;
 }



/** SM2_sign_setup
* precompute parts of the signing operation. 
* \param eckey pointer to the EC_KEY object containing a private EC key
* \param ctx  pointer to a BN_CTX object (may be NULL)
* \param k pointer to a BIGNUM pointer for the inverse of k
* \param rp   pointer to a BIGNUM pointer for x coordinate of k * generator
* \return 1 on success and 0 otherwise
 */

/*
int  SM2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
// 	ECDSA_DATA *ecdsa = ecdsa_check(eckey);
// 	if (ecdsa == NULL)
// 		return 0;
	return sm2_sign_setup(eckey, ctx_in, kinvp, rp); 
}
*/

/** SM2_sign_ex
 * computes ECDSA signature of a given hash value using the supplied
 * private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 * \param type this parameter is ignored
 * \param dgst pointer to the hash value to sign
 * \param dgstlen length of the hash value
 * \param sig buffer to hold the DER encoded signature
 * \param siglen pointer to the length of the returned signature
 * \param k optional pointer to a pre-computed inverse k
 * \param rp optional pointer to the pre-computed rp value (see 
 *        ECDSA_sign_setup
 * \param eckey pointer to the EC_KEY object containing a private EC key
 * \return 1 on success and 0 otherwise
 */
int	  SM2_sign_ex(const unsigned char *dgst, int dlen, unsigned char 
	*sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, 
	EC_KEY *eckey)
{
	ECDSA_SIG *s;

//	RAND_seed(dgst, dlen);

	s = sm2_do_sign(dgst, dlen, kinv, r, eckey);
	if (s == NULL)
	{
		*siglen=0;
		return 0;
	}
	*siglen = i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);
	return 1;
}


/** SM2_sign
  * computes ECDSA signature of a given hash value using the supplied
  * private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
  * \param type this parameter is ignored
  * \param dgst pointer to the hash value to sign
  * \param dgstlen length of the hash value
  * \param sig buffer to hold the DER encoded signature
  * \param siglen pointer to the length of the returned signature
  * \param eckey pointer to the EC_KEY object containing a private EC key
  * \return 1 on success and 0 otherwise
 */

/*
int	  SM2_sign(int type, const unsigned char *dgst, int dlen, unsigned char 
		*sig, unsigned int *siglen, EC_KEY *eckey)
{

	return SM2_sign_ex(type, dgst, dlen, sig, siglen, NULL, NULL, eckey);

}
*/

int	  SM2_sign(const unsigned char *dgst, int dlen, unsigned char 
		*sig, unsigned int *siglen, EC_KEY *eckey)
{
    
    
    
    return SM2_sign_ex(dgst, dlen, sig, siglen, NULL, NULL, eckey);




}

int CHN_SM2_INIT(const unsigned char *m, int m_len, 
	unsigned char *uID, int u_len, unsigned char *dgst)
{
//	RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */
	int ret = 0;

	
	//to get Z_A || M
	unsigned char Z_A[32];		//to store hash value Z, 32 bytes default
	unsigned char c_tmpBN[32];
	int tmp_len = 0;

    sm3_context ctx;
    int i;
	
	BIGNUM *tmpBN = BN_new();
	if (!tmpBN) 
		{
		fprintf(stdout, " failed\n");
		ABORT;
		}

//	unsigned char *ENTLA = (unsigned char *)"18";

	//sm3_context ctx;
	sm3_starts(&ctx);
	
	tmp_len = u_len*8;		//ENTLA, two bytes, converted from length of uID (unit: bit)
	c_tmpBN[0] = (unsigned char)(tmp_len>>8 & 0x00ff);
	c_tmpBN[1] = (unsigned char)(tmp_len & 0x00ff);
	sm3_update(&ctx, c_tmpBN, 2);

	sm3_update(&ctx, uID, u_len);

	if (!BN_hex2bn(&tmpBN, c_a)) ABORT;		//put in parameter a, converted from Hex mode to 
											//BIGNUM to binary mode (byte stream)
	tmp_len = BN_bn2bin(tmpBN, c_tmpBN);	
	sm3_update(&ctx, c_tmpBN, tmp_len);

	if (!BN_hex2bn(&tmpBN, c_b)) ABORT;		//put in parameter b
	tmp_len = BN_bn2bin(tmpBN, c_tmpBN);
	sm3_update(&ctx, c_tmpBN, tmp_len);

	if (!BN_hex2bn(&tmpBN, c_x)) ABORT;		//put in coordinates of point G
	tmp_len = BN_bn2bin(tmpBN, c_tmpBN);
	sm3_update(&ctx, c_tmpBN, tmp_len);

	if (!BN_hex2bn(&tmpBN, c_y)) ABORT;
	tmp_len = BN_bn2bin(tmpBN, c_tmpBN);
	sm3_update(&ctx, c_tmpBN, tmp_len);

	if (!BN_hex2bn(&tmpBN, c_xa)) ABORT;	//put in coordinates of point A, which is pubkey
	tmp_len = BN_bn2bin(tmpBN, c_tmpBN);
	sm3_update(&ctx, c_tmpBN, tmp_len);

	if (!BN_hex2bn(&tmpBN, c_ya)) ABORT;
	tmp_len = BN_bn2bin(tmpBN, c_tmpBN);
	sm3_update(&ctx, c_tmpBN, tmp_len);

	sm3_finish(&ctx, Z_A);					//generate Z_A

#ifdef DEBUG_PRINT

	printf("\nZ_A:\n");

	for (i=0; i<32; i++)
		printf("%02x", Z_A[i]);

#endif

	sm3_starts(&ctx);
	sm3_update(&ctx, Z_A, 32);
	sm3_update(&ctx, (unsigned char*)m, m_len);
	sm3_finish(&ctx, dgst);					//generate Z_A || M

#ifdef DEBUG_PRINT
	printf("\ndgst:\n");
	for (i=0; i<32; i++)
			printf("%02x", *(dgst+i));
#endif

	ret = 1;

err:
	BN_free(tmpBN);

	return ret;
}


int	  CHN_SM2_sign(const unsigned char *m, int m_len, 
unsigned char *uID, int u_len, unsigned char *sig, 
int *sig_len, unsigned char *pubkeyID, int *pubkeyID_len, EC_KEY *eckey)

{
    int ret; 
    sm3_context ctx;
    BIGNUM *tmpBN;
	int tmp_len;
	unsigned char c_tmpBN[32];

//	EC_KEY	*eckey = NULL;		//to store public and private key, and group parameters
	unsigned char	digest[32];		//to store hash output Z_A || M

	EC_KEY *eckey_tmp = EC_KEY_dup(eckey);
	if(eckey_tmp == NULL)	ABORT;

	
	//generate Z_A || M
	
	if(!CHN_SM2_INIT(m, m_len, uID, u_len, digest))
		{
			printf("\nErr in CHN_SM2_INIT!\n");
			ABORT;
		}
	
	//to get the pubkeyID, i.e., SM3 hash output of public key
	//sm3_context ctx;
	//BIGNUM *tmpBN = BN_new();
    tmpBN = BN_new();
	//int tmp_len;
	//unsigned char c_tmpBN[32];
	sm3_starts(&ctx);
		
	if (!BN_hex2bn(&tmpBN, c_xa)) ABORT;
	tmp_len = BN_bn2bin(tmpBN, c_tmpBN);
	sm3_update(&ctx, c_tmpBN, tmp_len);
	
	if (!BN_hex2bn(&tmpBN, c_ya)) ABORT;
	tmp_len = BN_bn2bin(tmpBN, c_tmpBN);
	sm3_update(&ctx, c_tmpBN, tmp_len);
	
	sm3_finish(&ctx, pubkeyID);
	*pubkeyID_len = tmp_len;


	/* create signature */
	//int ret = SM2_sign(digest,32, sig, sig_len, eckey_tmp);
    ret = SM2_sign(digest,32, sig, sig_len, eckey_tmp);

err:
	BN_free(tmpBN);
/*
	if (eckey)
		{
		EC_KEY_free(eckey);
		eckey = NULL;
		}
*/

	return ret;


}


/** SM2_verify
  * verifies that the given signature is valid ECDSA signature
  * of the supplied hash value using the specified public key.
  * \param type this parameter is ignored
  * \param dgst pointer to the hash value 
  * \param dgstlen length of the hash value
  * \param sig  pointer to the DER encoded signature
  * \param siglen length of the DER encoded signature
  * \param eckey pointer to the EC_KEY object containing a public EC key
  * \return 1 if the signature is valid, 0 if the signature is invalid and -1 on error
  */

int SM2_verify(const unsigned char *dgst, int dgst_len,
		const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
 {
	ECDSA_SIG *s;
	int ret=0;

	s = ECDSA_SIG_new();
	if (s == NULL) return(ret);
	//decode the DER code of signature
	if (d2i_ECDSA_SIG(&s, &sigbuf, sig_len) == NULL) goto err;

	ret=sm2_do_verify(dgst, dgst_len, s, eckey);
	
err:
	ECDSA_SIG_free(s);
	return(ret);
}



int	  CHN_SM2_verify(const unsigned char *m, int m_len, 
	unsigned char *uID, int u_len, unsigned char *sig, int sig_len, EC_KEY *eckey)
{


	int ret = 0;
	unsigned char	digest[32];

	EC_KEY *eckey_tmp = EC_KEY_dup(eckey);
	if(eckey_tmp == NULL)	ABORT;

	//generate Z_A || M
	if(!CHN_SM2_INIT(m, m_len, uID, u_len, digest))
		{
			printf("\nErr in CHN_SM2_INIT!\n");
			ABORT;
		}

#ifdef DEBUG_PRINT
	
	printf("\nsig_len before verify: %d\n", sig_len);
		
#endif

	if (sig == NULL)
		{
			fprintf(stdout, " failed\n");
			ABORT;
		}

	//verify the signature
	ret = SM2_verify(digest, 32, sig, sig_len, eckey_tmp);

err:

/*
	if (eckey)
		{
		EC_KEY_free(eckey);
		eckey = NULL;
		}
*/


/*
	
*/

	return ret;

}

