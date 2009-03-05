/* Copyright (c) 2007  "Guan Zhi" <guanzhi1980@gmail.com> */

#include <string.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include "cpk.h"
#include "ecies.h"


static ASN1_TYPE *get_attribute(STACK_OF(X509_ATTRIBUTE) *sk, int nid);
static int add_attribute(STACK_OF(X509_ATTRIBUTE) **sk,
	int nid, int atrtype, void *value);
static int bio_add_digest(BIO **pbio, X509_ALGOR *algor);


static ASN1_TYPE *get_attribute(STACK_OF(X509_ATTRIBUTE) *sk, int nid)
{
	int i;
	X509_ATTRIBUTE *xa;
	ASN1_OBJECT *o;

	o = OBJ_nid2obj(nid);
	if (!o || !sk) return NULL;

	for (i = 0; i < sk_X509_ATTRIBUTE_num(sk); i++) {
		xa = sk_X509_ATTRIBUTE_value(sk, i);
		if (OBJ_cmp(xa->object,o) == 0) {
			if (!xa->single && sk_ASN1_TYPE_num(xa->value.set))
				return sk_ASN1_TYPE_value(xa->value.set,0);
			else
				return NULL;
		}
	}

	return NULL;
}

/**
 *@param value will be added to x509 attribute stack,
 *	so value MUST NOT be free-ed after this function
 *	successful return.
 */
static int add_attribute(STACK_OF(X509_ATTRIBUTE) **sk,
	int nid, int atrtype, void *value)
{
	X509_ATTRIBUTE *attr = NULL;

	if (*sk == NULL) {
		if (!(*sk = sk_X509_ATTRIBUTE_new_null()))
			return 0;
new_attrib:
		if (!(attr = X509_ATTRIBUTE_create(nid, atrtype, value)))
			return 0;
		if (!sk_X509_ATTRIBUTE_push(*sk, attr)) {
			X509_ATTRIBUTE_free(attr);
			return 0;
		}
	} else {
		int i;
		for (i = 0; i < sk_X509_ATTRIBUTE_num(*sk); i++) {
			attr = sk_X509_ATTRIBUTE_value(*sk, i);
			if (OBJ_obj2nid(attr->object) == nid) {
				X509_ATTRIBUTE_free(attr);
				attr = X509_ATTRIBUTE_create(nid, atrtype, value);
				if (attr == NULL)
					return 0;
				if (!sk_X509_ATTRIBUTE_set(*sk, i, attr)) {
					X509_ATTRIBUTE_free(attr);
					return 0;
				}
				goto end;
			}
		}
		goto new_attrib;
	}
end:
	return 1;
}


CPK_SECRET_MATRIX *CPK_SECRET_MATRIX_create(
	const char *matrix_uri, const char *curve_name,
	const EVP_MD *map_md, unsigned int column_size,
	unsigned int row_size, void *rand_param)
{
	int e = 1;
	unsigned int i;
	unsigned char *p;	
	CPK_SECRET_MATRIX *msk = CPK_SECRET_MATRIX_new();
	EC_GROUP *ec_group = NULL;
	BIGNUM *order = BN_new();
	BIGNUM *bn = BN_new();
	int bnlen;
	
	
	/* simple check of arguments */
	OPENSSL_assert(matrix_uri);
	OPENSSL_assert(curve_name);
	OPENSSL_assert(map_md);
	OPENSSL_assert(0 < column_size && column_size <= CPK_MAX_COLUMN_SIZE);
	OPENSSL_assert(0 < row_size && row_size <= CPK_MAX_ROW_SIZE);

	if (!msk || !order || !bn) {
		CPKerr(CPK_F_CPK_SECRET_MATRIX_CREATE, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	
	/* set version */
	msk->version = CPK_CMS_VERSION;
	
	/* set matrix_uri */
	if (!ASN1_STRING_set((ASN1_UTF8STRING *)msk->matrix_uri,
		matrix_uri, (int)strlen(matrix_uri))) {
		CPKerr(CPK_F_CPK_SECRET_MATRIX_CREATE, ERR_R_ASN1_LIB);
		goto err;
	}
	
	/* set curve_obj */
	if (!(ec_group = EC_GROUP_new_by_curve_name(OBJ_sn2nid(curve_name)))){
		CPKerr(CPK_F_CPK_SECRET_MATRIX_CREATE, CPK_R_UNKNOWN_CURVE);
		goto err;
	}
	if (!(msk->curve_obj = OBJ_nid2obj(OBJ_sn2nid(curve_name)))) {
		CPKerr(CPK_F_CPK_SECRET_MATRIX_CREATE, CPK_R_UNKNOWN_CURVE);
		goto err;
	}
	
	/* set map_algor */
	/* FIXME: map algorithm object id should be assigned */
	if (!(msk->map_algor->algorithm = OBJ_nid2obj(EVP_MD_type(map_md)))) {
		CPKerr(CPK_F_CPK_SECRET_MATRIX_CREATE, 
			CPK_R_UNKNOWN_MAP_TYPE);
		goto err;
	}
	
	/* set column_size and row_size */
	msk->column_size = (long)column_size;
	msk->row_size = (long)row_size;

	/* generate random private keys (bignums) */
	/*   prepare memory */
	if (!EC_GROUP_get_order(ec_group, order, NULL)) {
		CPKerr(CPK_F_CPK_SECRET_MATRIX_CREATE, ERR_R_EC_LIB);
		goto err;
	}
	bnlen = BN_num_bytes(order);
	if (!ASN1_STRING_set(msk->bignums, 
		NULL, bnlen * column_size *row_size)) {
		CPKerr(CPK_F_CPK_SECRET_MATRIX_CREATE, ERR_R_ASN1_LIB);
		goto err;
	}
	memset(msk->bignums->data, 0, msk->bignums->length);

	/*  generation */
	p = msk->bignums->data;
	for (i = 0; i < column_size * row_size; i++) {
		do {
			/*
			 * if rand_param provide a user specific RNG,
			 * use this RNG engine to generate private keys,
			 * if not, use default openssl PRNG.
			 */
			if (rand_param == NULL) {
				if (!BN_pseudo_rand_range(bn, order)) {
					CPKerr(CPK_F_CPK_SECRET_MATRIX_CREATE,
						ERR_R_RAND_LIB);
					goto err;
				}
			} else {
				/*
				 * FIXME: OS RNG is used instead of user
				 * specific RNG.
				 */
				if (!BN_rand_range(bn, order)) {
					CPKerr(CPK_F_CPK_SECRET_MATRIX_CREATE,
						ERR_R_RAND_LIB);
					goto err;
				}
			}
			
		} while (BN_is_zero(bn));
		/* private key MUST NOT be zero */


		/* field element is big-endian encoded with fixed length */
		if (!BN_bn2bin(bn, p + bnlen - BN_num_bytes(bn))) {
			CPKerr(CPK_F_CPK_SECRET_MATRIX_CREATE, ERR_R_BN_LIB);
			goto err;
		}
		
		p += bnlen;
	}

	e = 0;

err:
	if (ec_group) EC_GROUP_free(ec_group);
	if (order) BN_free(order);
	if (bn) BN_free(bn);
	if (e && msk) {
		CPK_SECRET_MATRIX_free(msk);
		msk = NULL;
	}

	return msk;
}

CPK_PUBLIC_MATRIX *CPK_PUBLIC_MATRIX_create(
	const CPK_SECRET_MATRIX *msk, int pt_compressed)
{
	int e = 1, i;
	CPK_PUBLIC_MATRIX *mpk = CPK_PUBLIC_MATRIX_new();
	EC_GROUP *ec_group = NULL;
	EC_POINT *pt = NULL;
	BIGNUM *order = BN_new();
	BIGNUM *bn = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	int pt_form;
	int pt_size, bn_size;
	unsigned char *bn_ptr, *pt_ptr;
	unsigned char pt_buf[128];

	// version
	if (msk->version != CPK_CMS_VERSION) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, CPK_R_BAD_DATA);
		goto err;
	}
	mpk->version = msk->version;
	
	// matrix_uri
	if (msk->matrix_uri == NULL || msk->matrix_uri->data == NULL ||
		msk->matrix_uri->length <= 0) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, CPK_R_BAD_DATA);
		goto err;
	}
	if (!ASN1_STRING_set((ASN1_STRING *)mpk->matrix_uri,
		msk->matrix_uri->data, msk->matrix_uri->length)) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, ERR_R_ASN1_LIB);
		goto err;
	}
	
	// curve_obj
	// ASN1_OBJECT is static inner value
	mpk->curve_obj = msk->curve_obj;

	// map_algor
	X509_ALGOR_free(mpk->map_algor);
	if (!(mpk->map_algor = X509_ALGOR_dup(msk->map_algor))) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, ERR_R_X509_LIB);
		goto err;
	}
	
	// column_size, row_size
	mpk->column_size = msk->column_size;
	mpk->row_size = msk->row_size;

	// points
	if (!(ec_group = EC_GROUP_new_by_curve_name(
		OBJ_obj2nid(msk->curve_obj)))) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, CPK_R_UNKNOWN_CURVE);
		goto err;
	}
	if (!(pt = EC_POINT_new(ec_group))) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!(EC_GROUP_get_order(ec_group, order, ctx))) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, ERR_R_EC_LIB);
		goto err;
	}
	
	bn_size = BN_num_bytes(order);
	if (pt_compressed) {
		pt_form = POINT_CONVERSION_COMPRESSED;
		pt_size = bn_size + 1;
	} else {
		pt_form = POINT_CONVERSION_UNCOMPRESSED;
		pt_size = bn_size * 2;
	}

	if (!ASN1_STRING_set((ASN1_STRING *)mpk->points, 
		NULL, msk->column_size * msk->row_size * pt_size + 1)) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	bn_ptr = msk->bignums->data;
	pt_ptr = mpk->points->data + 1;
	mpk->points->data[0] = pt_compressed ? 1 : 0;

	for (i = 0; i < msk->column_size * msk->row_size; i++) {	
		if (!BN_bin2bn(bn_ptr, bn_size, bn)) {
			CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, ERR_R_BN_LIB);
			goto err;
		}
		if (BN_is_zero(bn) || BN_cmp(bn, order) >= 0) {
			CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, CPK_R_BAD_DATA);
			goto err;
		}
		if (!EC_POINT_mul(ec_group, pt, bn, NULL, NULL, ctx)) {
			CPKerr(CPK_F_CPK_PUBLIC_MATRIX_CREATE, ERR_R_EC_LIB);
			goto err;
		}
		EC_POINT_point2oct(ec_group, pt, pt_form, 
			pt_buf, sizeof(pt_buf), ctx);
		
		if (pt_compressed)
			memcpy(pt_ptr, pt_buf, pt_size);
		else	memcpy(pt_ptr, pt_buf + 1, pt_size);

		bn_ptr += bn_size;
		pt_ptr += pt_size;
	}

	e = 0;

err:
	if (ec_group) EC_GROUP_free(ec_group);
	if (pt) EC_POINT_free(pt);
	if (bn) BN_free(bn);
	if (order) BN_free(order);
	if (ctx) BN_CTX_free(ctx);

	if (e && mpk) {
		CPK_PUBLIC_MATRIX_free(mpk);
		mpk = NULL;
	}

	return mpk;
}

EC_KEY *CPK_PUBLIC_MATRIX_get_key(const CPK_PUBLIC_MATRIX *mpk,
	const CPK_IDENTITY_INFO *id)
{
	int e = 1, i;
	const EC_GROUP *ec_group = NULL;
	unsigned char pt_buf[160];
	int bn_size, pt_size;
	int pt_compressed;

	EC_KEY *ec_key = NULL;
	EC_POINT *pt = NULL, *rpt = NULL;
	BIGNUM *order = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	int *index = (int *)OPENSSL_malloc(sizeof(int) * mpk->column_size);
	

	if (!order || !ctx || !index) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	// init
	if (!(ec_key = EC_KEY_new_by_curve_name(
		OBJ_obj2nid(mpk->curve_obj)))) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY, CPK_R_UNKNOWN_CURVE);
		goto err;
	}
	ec_group = EC_KEY_get0_group(ec_key);
	if (!(pt = EC_POINT_new(ec_group))) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY, ERR_R_EC_LIB);
		goto err;
	}
	if (!(rpt = EC_POINT_new(ec_group))) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY, ERR_R_EC_LIB);
		goto err;
	}
	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY, ERR_R_EC_LIB);
		goto err;
	}

	// prepare
	bn_size = BN_num_bytes(order);

	pt_compressed = mpk->points->data[0];
	if (pt_compressed)
		pt_size = bn_size + 1;
	else	pt_size = bn_size * 2;

	if (mpk->points->length != 
		pt_size * mpk->column_size * mpk->row_size + 1) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY, CPK_R_BAD_DATA);
		goto err;
	}
	
	// check points size is correct and gen index
	{
		const EVP_MD *md = NULL;
		if (!(md = EVP_get_digestbyobj(mpk->map_algor->algorithm))) {
			CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY,
				CPK_R_UNKNOWN_MAP_TYPE);
			goto err;
		}
		if (!str2index(md, mpk->column_size, mpk->row_size, 
			id->id_data->data, id->id_data->length, index)) {
			CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY,
				CPK_R_MAP_FAILED);
			goto err;
		}
	}

	if (!EC_POINT_set_to_infinity(ec_group, rpt)) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY, ERR_R_EC_LIB);
		goto err;
	}
	pt_buf[0] = (unsigned char)pt_compressed;	
	for (i = 0; i < mpk->column_size; i++) {
		unsigned char *pt_ptr;
		pt_ptr = mpk->points->data + 1 + pt_size * index[i];		

		if (pt_compressed)
			memcpy(pt_buf, pt_ptr, pt_size);
		else	memcpy(pt_buf + 1, pt_ptr, pt_size);

		if (!EC_POINT_oct2point(ec_group, pt, pt_buf, pt_size, ctx)) {
			CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY, CPK_R_BAD_DATA);
			goto err;
		}
		if (!EC_POINT_add(ec_group, rpt, rpt, pt, ctx)) {
			CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY, ERR_R_EC_LIB);
			goto err;
		}
	}

	if (!EC_KEY_set_public_key(ec_key, rpt)) {
		CPKerr(CPK_F_CPK_PUBLIC_MATRIX_GET_KEY, ERR_R_EC_LIB);
		goto err;
	}

	e = 0;
err:
	if (rpt) EC_POINT_free(rpt);
	if (pt) EC_POINT_free(pt);
	if (order) BN_free(order);
	if (ctx) BN_CTX_free(ctx);
	if (index) OPENSSL_free(index);
	if (e && ec_key) {
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}

	return ec_key;
}

int CPK_IDENTITY_INFO_set(CPK_IDENTITY_INFO *id, ASN1_UTF8STRING *matrix_uri,
	int id_schema, const char *id_data, size_t id_data_len,
	const CPK_PUBLIC_MATRIX *public_matrix, const EC_KEY *ec_key)
{
	if (matrix_uri) {
		if (!ASN1_STRING_set((ASN1_STRING *)id->matrix_uri,
			matrix_uri->data, matrix_uri->length)) {
			CPKerr(CPK_F_CPK_IDENTITY_INFO_SET, ERR_R_ASN1_LIB);
			goto err;
		}
	}

	// id_schema is a object identifier
	// the cpk library should add more object functions
	// into the OpenSSL library
	//id->id_schema = OBJ_nid2obj(id_schema);

	if (id_data) {
		if (!ASN1_STRING_set((ASN1_STRING *)id->id_data, 
			id_data, (int)id_data_len)) {
			CPKerr(CPK_F_CPK_IDENTITY_INFO_SET, ERR_R_ASN1_LIB);
			goto err;
		}
	}

	if (public_matrix) {
		// set id->matrix_uri and id->public_matrix
		if (!ASN1_STRING_set((ASN1_STRING *)id->matrix_uri, 
			public_matrix->matrix_uri->data,
			public_matrix->matrix_uri->length)) {
			CPKerr(CPK_F_CPK_IDENTITY_INFO_SET, ERR_R_ASN1_LIB);
			goto err;
		}
		id->public_matrix = public_matrix;
	}

	if (ec_key) {
		id->public_key = ec_key;

		if (id->public_matrix) {
			EC_KEY *tmp_key = NULL;
			if (!(tmp_key = CPK_PUBLIC_MATRIX_get_key(id->public_matrix, id))) {
				goto err;
			}
			if (!EC_POINT_cmp(EC_KEY_get0_group(tmp_key), EC_KEY_get0_public_key(tmp_key),
				EC_KEY_get0_public_key(id->public_key), NULL)) {
				goto err;
			}
		}
	}

	return 1;
err:
	return 0;
}

CPK_IDENTITY_INFO *CPK_IDENTITY_INFO_dup(const CPK_IDENTITY_INFO *id)
{
	CPK_IDENTITY_INFO *ret;
	if (!(ret = CPK_IDENTITY_INFO_new())) {
		return NULL;
	}
	if (!CPK_IDENTITY_INFO_set(ret, id->matrix_uri, 0, 
		id->id_data->data, id->id_data->length, 
		id->public_matrix, id->public_key)) {
		CPK_IDENTITY_INFO_free(ret);
		return NULL;
	}
	return ret;
}

int CPK_IDENTITY_INFO_cmp(const CPK_IDENTITY_INFO *id, const CPK_IDENTITY_INFO *id2)
{
	if (id->matrix_uri->length != id2->matrix_uri->length)
		return 1;
	if (memcmp(id->matrix_uri->data, id2->matrix_uri->data,
		id->matrix_uri->length))
		return 1;
	// FIXME: id_schema
	if (id->id_data->length != id2->id_data->length)
		return 1;
	if (memcmp(id->id_data->data, id2->id_data->data, id->id_data->length))
		return 1;

	return 0;
}

EC_KEY *CPK_IDENTITY_INFO_get_key(const CPK_IDENTITY_INFO *id)
{
	EC_KEY *ec_key = NULL;

	// if the public_key attribute exists, 
	// return the dup of the inner public key
	// else create a new key from public_matrix and id_data
	
	if (id->public_key) {
		if (!(ec_key = EC_KEY_dup(id->public_key))) {
			return NULL;
		}
		return ec_key;
	}

	if (id->public_key == NULL &&
		(id->id_data->data == NULL || id->id_data->length <= 0)) {
		CPKerr(CPK_F_CPK_IDENTITY_INFO_GET_KEY,
			ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return NULL;
	}

	if (!(ec_key = CPK_PUBLIC_MATRIX_get_key(id->public_matrix, id))) {
		CPKerr(CPK_F_CPK_IDENTITY_INFO_GET_KEY,
			CPK_R_DERIVE_KEY_FAILED);
		return NULL;
	}

	return ec_key;
}

CPK_KEY_INFO *CPK_KEY_INFO_create(const CPK_SECRET_MATRIX *msk,
	const CPK_IDENTITY_INFO *id)
{
	int e = 1, i;
	CPK_KEY_INFO *ki = CPK_KEY_INFO_new();
	EC_GROUP *ec_group = NULL;
	BIGNUM *order = BN_new();
	BIGNUM *rbn = BN_new();
	BIGNUM *bn = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	int *index = (int *)OPENSSL_malloc(sizeof(int) * msk->column_size);
	const EVP_MD *md = NULL;
	int bn_size = 0;

	if (!ki || !order || !rbn || !bn || !ctx || !index) {
		CPKerr(CPK_F_CPK_KEY_INFO_CREATE, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	// set version, identity, curve_obj
	ki->version = CPK_CMS_VERSION;
	ki->curve_obj = msk->curve_obj;
	
	CPK_IDENTITY_INFO_free(ki->identity);
	if (!(ki->identity = CPK_IDENTITY_INFO_dup(id))) {
		CPKerr(CPK_F_CPK_KEY_INFO_CREATE, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!(ec_group = EC_GROUP_new_by_curve_name(
		OBJ_obj2nid(msk->curve_obj)))) {
		CPKerr(CPK_F_CPK_KEY_INFO_CREATE, CPK_R_UNKNOWN_CURVE);
		goto err;
	}
	if (!EC_GROUP_get_order(ec_group, order, NULL)) {
		CPKerr(CPK_F_CPK_KEY_INFO_CREATE, ERR_R_EC_LIB);
		goto err;
	}
	bn_size = BN_num_bytes(order);

	// gen index
	if (!(md = EVP_get_digestbyobj(msk->map_algor->algorithm))) {
		CPKerr(CPK_F_CPK_KEY_INFO_CREATE, CPK_R_UNKNOWN_DIGEST_TYPE);
		goto err;
	}
	if (!str2index(md, msk->column_size, msk->row_size,
		id->id_data->data, id->id_data->length, index)) {
		CPKerr(CPK_F_CPK_KEY_INFO_CREATE, CPK_R_MAP_FAILED);
		goto err;
	}
	
	// gen private key
	BN_zero(rbn);
	for (i = 0; i < msk->column_size; i++) {
		unsigned char *bn_ptr;
		bn_ptr = msk->bignums->data + bn_size * index[i];

		if (!BN_bin2bn(bn_ptr, bn_size, bn)) {
			CPKerr(CPK_F_CPK_KEY_INFO_CREATE, CPK_R_BAD_DATA);
			goto err;
		}
		if (!BN_mod_add(rbn, rbn, bn, order, ctx)) {
			CPKerr(CPK_F_CPK_KEY_INFO_CREATE, ERR_R_BN_LIB);
			goto err;
		}
	}

	// set private key
	{
		ASN1_INTEGER *asn1;
		unsigned char *p;

		if (!(asn1 = BN_to_ASN1_INTEGER(rbn, NULL))) {
			CPKerr(CPK_F_CPK_KEY_INFO_CREATE, ERR_R_BN_LIB);
			goto err;
		}
		ki->key_data->length = i2d_ASN1_INTEGER(asn1, NULL);
		if (!(ki->key_data->data = (unsigned char *)
			OPENSSL_malloc(ki->key_data->length))) {
			CPKerr(CPK_F_CPK_KEY_INFO_CREATE,
				ERR_R_MALLOC_FAILURE);
			ASN1_INTEGER_free(asn1);
			goto err;
		}
		p = ki->key_data->data;
		i2d_ASN1_INTEGER(asn1, &p);
		ASN1_INTEGER_free(asn1);
	}
	
	e = 0;

err:
	if (ec_group) EC_GROUP_free(ec_group);
	if (order) BN_free(order);
	if (rbn) BN_free(rbn);
	if (bn) BN_free(bn);
	if (ctx) BN_CTX_free(ctx);
	if (index) OPENSSL_free(index);
	if (e && ki) {
		CPK_KEY_INFO_free(ki);
		ki = NULL;
	}

	return ki;
}


EC_KEY *CPK_KEY_INFO_get_key(const CPK_KEY_INFO *ki)
{
	int e = 1;
	EC_KEY *ec_key = NULL;
	BIGNUM *bn = NULL;
	BIGNUM *order = NULL;
	BN_CTX *ctx = NULL;

	if (ki->ec_key) {
		if (!(ec_key = EC_KEY_dup(ki->ec_key)))
			CPKerr(CPK_F_CPK_KEY_INFO_GET_KEY, ERR_R_EC_LIB);
		return ec_key;
	}

	if (!(bn = BN_new()) || !(order = BN_new()) || !(ctx = BN_CTX_new())) {
		CPKerr(CPK_F_CPK_KEY_INFO_GET_KEY, ERR_R_BN_LIB);
		goto err;
	}
	if (!(ec_key = EC_KEY_new_by_curve_name(
		OBJ_obj2nid(ki->curve_obj)))) {
		CPKerr(CPK_F_CPK_KEY_INFO_GET_KEY, CPK_R_UNKNOWN_CURVE);
		goto err;
	}
	if (!EC_GROUP_get_order(EC_KEY_get0_group(ec_key), order, ctx)) {
		CPKerr(CPK_F_CPK_KEY_INFO_GET_KEY, ERR_R_EC_LIB);
		goto err;
	}

	{
		ASN1_INTEGER *asn1 = NULL;
		const unsigned char *cp = ki->key_data->data;

		if (!(asn1 = d2i_ASN1_INTEGER(NULL, &cp, ki->key_data->length))) {
			CPKerr(CPK_F_CPK_KEY_INFO_GET_KEY, CPK_R_BAD_DATA);
			goto err;
		}
		if (!(bn = ASN1_INTEGER_to_BN(asn1, NULL))) {
			CPKerr(CPK_F_CPK_KEY_INFO_GET_KEY, ERR_R_ASN1_LIB);
			ASN1_INTEGER_free(asn1);
			goto err;
		}
		ASN1_INTEGER_free(asn1);
	}

	// chech private key value
	if (BN_cmp(bn, order) >= 0 || BN_is_zero(bn)) {
		CPKerr(CPK_F_CPK_KEY_INFO_GET_KEY, CPK_R_BAD_DATA);
		goto err;
	}
	if (!EC_KEY_set_private_key(ec_key, bn)) {
		CPKerr(CPK_F_CPK_KEY_INFO_GET_KEY, ERR_R_EC_LIB);
		goto err;
	}

	e = 0;
err:
	if (bn) BN_free(bn);
	if (order) BN_free(order);
	if (ctx) BN_CTX_free(ctx);
	if (e && ec_key) {
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}

	return ec_key;
}

int CPK_SIGNER_INFO_set(CPK_SIGNER_INFO *si, const EVP_MD *sign_alg, 
	const CPK_KEY_INFO *sign_key)
{
	si->version = CPK_CMS_VERSION;

	if (sign_alg) {
		if (!(si->digest_algor->algorithm = 
			OBJ_nid2obj(EVP_MD_type(sign_alg)))) {
			CPKerr(CPK_F_CPK_SIGNER_INFO_SET, 
				CPK_R_UNKNOWN_DIGEST_TYPE);
			goto err;
		}
		si->sign_algor->algorithm = si->digest_algor->algorithm;
	}

	if (sign_key) {
		if (si->signer)
			CPK_IDENTITY_INFO_free(si->signer);
		if (!(si->signer = CPK_IDENTITY_INFO_dup(sign_key->identity))) {
			goto err;
		}
		si->sign_key = sign_key;
	}

	return 1;
err:
	return 0;
}

int CPK_SIGNER_INFO_add_attr(CPK_SIGNER_INFO *si,
	int nid, int atrtype, void *value)
{
	return add_attribute(&(si->unauth_attr), nid, atrtype, value);
}

int CPK_SIGNER_INFO_add_signed_attr(CPK_SIGNER_INFO *si,
	int nid, int atrtype, void *value)
{
	return add_attribute(&(si->auth_attr), nid, atrtype,value);
}

int CPK_SIGNER_INFO_add_signed_time(CPK_SIGNER_INFO *si)
{
	ASN1_UTCTIME *sign_time = NULL;	
	
	/* add current time into signer info */
	if (!(sign_time = X509_gmtime_adj(NULL, 0))) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_ADD_SIGNED_TIME,
			ERR_R_X509_LIB);
		return 0;
	}
	
	return CPK_SIGNER_INFO_add_signed_attr(si, NID_pkcs9_signingTime,
		V_ASN1_UTCTIME, (char *)sign_time);
}

/**
 * Add the digest of content into signer info as a checksum,
 * it can be checked before verify the signature.
 */
int CPK_SIGNER_INFO_add_signed_digest(CPK_SIGNER_INFO *si,
	const EVP_MD_CTX *ctx)
{
	int r = 0;
	ASN1_OCTET_STRING *os = NULL;
	EVP_MD_CTX tmp_ctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_size;

	EVP_MD_CTX_init(&tmp_ctx);

	/* 
	 * the digest operation will change the context,
	 * and input context may be used by sign procedure to
	 * generate digest value, so we create a copy of it.
	 */ 
	if (!EVP_MD_CTX_copy(&tmp_ctx, ctx)) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_ADD_SIGNED_DIGEST, 
			ERR_R_EVP_LIB);
		goto err;
	}
	if (!EVP_DigestFinal(&tmp_ctx, digest, &digest_size)) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_ADD_SIGNED_DIGEST,
			ERR_R_EVP_LIB);
		goto err;
	}
	if (!(os = ASN1_OCTET_STRING_new())) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_ADD_SIGNED_DIGEST,
			ERR_R_ASN1_LIB);
		goto err;
	}
	if (!ASN1_OCTET_STRING_set(os, digest, digest_size)) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_ADD_SIGNED_DIGEST,
			ERR_R_ASN1_LIB);
		goto err;
	}
	if (!CPK_SIGNER_INFO_add_signed_attr(si, NID_pkcs9_messageDigest,
		V_ASN1_OCTET_STRING, os)) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_ADD_SIGNED_DIGEST,
			ERR_R_CPK_LIB);
		goto err;
	}

	os = NULL;
	r = 1;
err:
	if (os) ASN1_OCTET_STRING_free(os);
	EVP_MD_CTX_cleanup(&tmp_ctx);
	return r;
}

int CPK_SIGNER_INFO_do_sign(CPK_SIGNER_INFO *si, EVP_MD_CTX *ctx)
{
	int r = 0;
	const EVP_MD *md = EVP_MD_CTX_md(ctx);
	STACK_OF(X509_ATTRIBUTE) *sk = si->auth_attr;
	EC_KEY *tmp_key = NULL;

	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned char sig[256];
	unsigned char *abuf = NULL;
	int digest_size, siglen, alen;

	// add signed attributes to ctx and get digest
	if (sk && sk_num(sk) > 0) {
		if (!EVP_DigestInit_ex(ctx, md, NULL)) {
			CPKerr(CPK_F_CPK_SIGNER_INFO_DO_SIGN,
				CPK_R_DIGEST_FAILED);
			goto err;
		}
		alen = ASN1_item_i2d((ASN1_VALUE *)sk, &abuf,
			ASN1_ITEM_rptr(CPK_PKCS7_ATTR_SIGN));
		if (!abuf) {
			CPKerr(CPK_F_CPK_SIGNER_INFO_DO_SIGN, ERR_R_ASN1_LIB);
			goto err;
		}
		if (!EVP_DigestUpdate(ctx, abuf, alen)) {
			CPKerr(CPK_F_CPK_SIGNER_INFO_DO_SIGN,
				CPK_R_DIGEST_FAILED);
			goto err;
		}
	}
	if (!EVP_DigestFinal_ex(ctx, digest, &digest_size)) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_DO_SIGN, CPK_R_DIGEST_FAILED);
		goto err;
	}

	if (!(tmp_key = CPK_KEY_INFO_get_key(si->sign_key))) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_DO_SIGN, CPK_R_DERIVE_KEY_FAILED);
		goto err;
	}
	if (!ECDSA_sign(0, digest, digest_size, sig, &siglen, tmp_key)) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_DO_SIGN, ERR_R_ECDSA_LIB);
		goto err;
	}
	if (!ASN1_STRING_set((ASN1_STRING *)si->signature, sig, siglen)) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_DO_SIGN, ERR_R_ASN1_LIB);
		goto err;
	}
	
	r = 1;
err:
	if (tmp_key) EC_KEY_free(tmp_key);
	return r;
}


ASN1_TYPE *CPK_SIGNER_INFO_get_attr(CPK_SIGNER_INFO *si, int nid)
{
	return get_attribute(si->unauth_attr, nid);
}

ASN1_TYPE *CPK_SIGNER_INFO_get_signed_attr(CPK_SIGNER_INFO *si, int nid)
{
	return get_attribute(si->auth_attr, nid);
}

ASN1_UTCTIME *CPK_SIGNER_INFO_get_signed_time(CPK_SIGNER_INFO *si)
{
	ASN1_TYPE *so;

	so = CPK_SIGNER_INFO_get_signed_attr(si, NID_pkcs9_signingTime);
	if (so->type == V_ASN1_UTCTIME)
		return so->value.utctime;
	return NULL;
}

int CPK_SIGNER_INFO_do_verify(const CPK_SIGNER_INFO *si, EVP_MD_CTX *ctx,
	const CPK_PUBLIC_MATRIX *mpk)
{
	int r = 0;
	const EVP_MD *md = EVP_MD_CTX_md(ctx);
	STACK_OF(X509_ATTRIBUTE) *sk = si->auth_attr;
	unsigned char *abuf = NULL;
	int alen;
	EC_KEY *ec_key = NULL;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_size;

	// get veri_key from public_matrix
	// update auth_attr to digest context
	// compute the final digest
	// verify 

	if (sk && sk_num(sk) > 0) {
		if (!EVP_DigestInit_ex(ctx, md, NULL)) {
			goto err;
		}
		alen = ASN1_item_i2d((ASN1_VALUE *)sk, &abuf,
			ASN1_ITEM_rptr(CPK_PKCS7_ATTR_SIGN));
		if (!abuf) {
			CPKerr(CPK_F_CPK_SIGNER_INFO_DO_VERIFY, ERR_R_ASN1_LIB);
			goto err;
		}
		if (!EVP_DigestUpdate(ctx, abuf, (size_t)alen)) {
			CPKerr(CPK_F_CPK_SIGNER_INFO_DO_VERIFY, CPK_R_DIGEST_FAILED);
			goto err;
		}
	}
	if (!EVP_DigestFinal_ex(ctx, digest, &digest_size)) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_DO_VERIFY, CPK_R_DIGEST_FAILED);
		goto err;
	}

	if (!(ec_key = CPK_PUBLIC_MATRIX_get_key(mpk, si->signer))) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_DO_VERIFY,
			CPK_R_DERIVE_KEY_FAILED);
		goto err;
	}

	if (!ECDSA_verify(0, digest, (int)digest_size, si->signature->data, 
		si->signature->length, ec_key)) {
		CPKerr(CPK_F_CPK_SIGNER_INFO_DO_VERIFY, CPK_R_VERIFY_FAILED);
		goto err;
	}

	r = 1;
err:
	if (abuf) OPENSSL_free(abuf);
	if (ec_key) EC_KEY_free(ec_key);
	return r;
}


int CPK_RECIP_INFO_set(CPK_RECIP_INFO *ri,
	const CPK_IDENTITY_INFO *recipient, const ECIES_PARAMS *params)
{
	
	OPENSSL_assert(ri);
	
	ri->version = CPK_CMS_VERSION;

	/*
	 * argument recipient and params can be separated setted.
	 */

	if (params) {
		ri->enc_params = *params;
		if (!(ri->enc_algor->algorithm = 
			OBJ_nid2obj(EVP_MD_type(params->dh_kdf_md)))) {
			CPKerr(CPK_F_CPK_RECIP_INFO_SET,
				CPK_R_UNKNOWN_ECDH_TYPE);
			goto err;
		}
	}
	
	if (recipient) {
		if (ri->recipient)
			CPK_IDENTITY_INFO_free(ri->recipient);
		if (!(ri->recipient = CPK_IDENTITY_INFO_dup(recipient))) {
			CPKerr(CPK_F_CPK_RECIP_INFO_SET,
				ERR_R_MALLOC_FAILURE);
			goto err;
		}
		ri->recipient->public_matrix = recipient->public_matrix;
	}

	return 1;
err:
	return 0;
}

int CPK_RECIP_INFO_do_encrypt(CPK_RECIP_INFO *ri, 
	const unsigned char *in, size_t inlen)
{
	int r = 0, len;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	EC_KEY *tmp_key = NULL;
	const EC_KEY *ec_key;
	unsigned char *p;

	OPENSSL_assert(ri && in && inlen > 0);


	// get ec_key
	if (!(ec_key = CPK_IDENTITY_INFO_get0_key(ri->recipient))) {
		if (!(tmp_key = CPK_IDENTITY_INFO_get_key(ri->recipient))) {
			CPKerr(CPK_F_CPK_RECIP_INFO_DO_ENCRYPT,
				CPK_R_DERIVE_KEY_FAILED);
			goto err;
		}
		ec_key = tmp_key;
	}

	// encrypt
	if (!(cv = ECIES_do_encrypt(&ri->enc_params, in, inlen, ec_key))) {
		CPKerr(CPK_F_CPK_RECIP_INFO_DO_ENCRYPT,
			CPK_R_ECIES_ENCRYPT_FAILED);
		goto err;
	}

	// set enc_data
	len = i2d_ECIES_CIPHERTEXT_VALUE(cv, NULL);
	if (ri->enc_data->data == NULL) {
		if (!(ri->enc_data->data = (unsigned char *)
			OPENSSL_malloc(len))) {
			CPKerr(CPK_F_CPK_RECIP_INFO_DO_ENCRYPT,
				ERR_R_MALLOC_FAILURE);
			goto err;
		}
	} else if (ri->enc_data->length < len) {
		if (!(ri->enc_data->data = (unsigned char *)
			OPENSSL_realloc(ri->enc_data->data, len))) {
			CPKerr(CPK_F_CPK_RECIP_INFO_DO_ENCRYPT,
				ERR_R_MALLOC_FAILURE);
			goto err;
		}
	}
	ri->enc_data->length = len;
	p = ri->enc_data->data;
	i2d_ECIES_CIPHERTEXT_VALUE(cv, &p);
	
	r = 1;
err:	
	if (cv) ECIES_CIPHERTEXT_VALUE_free(cv);
	if (tmp_key) EC_KEY_free(tmp_key);
	return r;
}

int CPK_RECIP_INFO_do_decrypt(CPK_RECIP_INFO *ri,
	const CPK_KEY_INFO *ki, unsigned char *out, size_t *outlen)
{
	int r = 0;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	EC_KEY *tmp_key = NULL;
	const EC_KEY *ec_key;
	const unsigned char *cp;

	// get ec_key
	if (!(ec_key = CPK_KEY_INFO_get0_key(ki))) {
		if (!(tmp_key = CPK_KEY_INFO_get_key(ki))) {
			CPKerr(CPK_F_CPK_RECIP_INFO_DO_DECRYPT,
				CPK_R_BAD_ARGUMENT);
			goto err;
		}
		ec_key = tmp_key;
	}

	//ri->enc_params.is_cofator_dh = 0;
	if (!(ri->enc_params.dh_kdf_md = 
		EVP_get_digestbyobj(ri->enc_algor->algorithm))) {
		CPKerr(CPK_F_CPK_RECIP_INFO_DO_DECRYPT,
			CPK_R_UNKNOWN_DIGEST_TYPE);
		goto err;
	}
	
	cp = ri->enc_data->data;
	if (!(cv = d2i_ECIES_CIPHERTEXT_VALUE(
		NULL, &cp, ri->enc_data->length))) {
		CPKerr(CPK_F_CPK_RECIP_INFO_DO_DECRYPT, 
			CPK_R_DER_DECODE_FAILED);
		goto err;
	}
	if (!ECIES_do_decrypt(cv, &ri->enc_params, out, outlen, ec_key)) {
		CPKerr(CPK_F_CPK_RECIP_INFO_DO_DECRYPT,
			CPK_R_ECIES_DECRYPT_FAILED);
		goto err;
	}
	
	r = 1;
err:
	if (cv) ECIES_CIPHERTEXT_VALUE_free(cv);
	if (tmp_key) EC_KEY_free(tmp_key);
	return r;
}
