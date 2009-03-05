/* Copyright (c) 2007  "Guan Zhi" <guanzhi1980@gmail.com> */

#include <openssl/rand.h>
#include "cpk.h"

static int bio_add_digest(BIO **pbio, X509_ALGOR *algor)
{
	BIO *digest_bio = NULL;
	const EVP_MD *md = NULL;

	if (!(md = EVP_get_digestbyobj(algor->algorithm))) {
		CPKerr(CPK_F_BIO_ADD_DIGEST, CPK_R_UNKNOWN_DIGEST_TYPE);
		goto err;
	}
	if (!(digest_bio = BIO_new(BIO_f_md()))) {
		CPKerr(CPK_F_BIO_ADD_DIGEST, ERR_R_BIO_LIB);
		goto err;
	}
	BIO_set_md(digest_bio, md);

	if (*pbio == NULL)
		*pbio = digest_bio;
	else if (!BIO_push(*pbio, digest_bio)) {
		CPKerr(CPK_F_BIO_ADD_DIGEST, ERR_R_BIO_LIB);
		goto err;
	}
	digest_bio = NULL;

	return 1;
err:
	if (digest_bio) BIO_free(digest_bio);
	return 0;
}

static int bio_add_cipher(BIO **pbio, X509_ALGOR *algor, 
	const EVP_CIPHER *cipher, unsigned char *key, int enc)
{
	BIO *cipher_bio = NULL;
	EVP_CIPHER_CTX *cipher_ctx;
	int ivlen;

	if (!(cipher_bio = BIO_new(BIO_f_cipher()))) {
		CPKerr(CPK_F_BIO_ADD_CIPHER, ERR_R_BIO_LIB);
		goto err;
	}
	BIO_get_cipher_ctx(cipher_bio, &cipher_ctx);

	// init cipher_ctx without iv
	if (!EVP_CipherInit_ex(cipher_ctx, cipher, NULL, key, NULL, enc)) {
		goto err;
	}

	if (enc) {
		algor->algorithm = OBJ_nid2obj(EVP_CIPHER_type(cipher));
		OPENSSL_assert(algor->algorithm);
	}

	// add or get iv from algor->parameter
	// add iv to cipher_ctx
	ivlen = EVP_CIPHER_iv_length(cipher);
	if (ivlen > 0) {
		if (enc) {
			unsigned char iv[EVP_MAX_BLOCK_LENGTH];
			if (RAND_pseudo_bytes(iv, ivlen) <= 0) {
				CPKerr(CPK_F_BIO_ADD_CIPHER, ERR_R_RAND_LIB);
				goto err;
			}
			if (!EVP_CipherInit_ex(cipher_ctx,
				NULL, NULL, NULL, iv, enc)) {
				CPKerr(CPK_F_BIO_ADD_CIPHER, ERR_R_EVP_LIB);
				goto err;
			}
			if (algor->parameter == NULL) {
				if (!(algor->parameter = ASN1_TYPE_new())) {
					CPKerr(CPK_F_BIO_ADD_CIPHER, 
						ERR_R_ASN1_LIB);
					goto err;
				}
			}
			if (!EVP_CIPHER_param_to_asn1(cipher_ctx, 
				algor->parameter)) {
				CPKerr(CPK_F_BIO_ADD_CIPHER, ERR_R_EVP_LIB);
				goto err;
			}
		} else {
			if (!EVP_CIPHER_asn1_to_param(cipher_ctx, 
				algor->parameter)) {
				// prone to be error
				// parameter might be null, 
				// ivlen maybe not enough
				CPKerr(CPK_F_BIO_ADD_CIPHER, ERR_R_EVP_LIB);
				goto err;
			}
		}
	} 

	if (*pbio == NULL)
		*pbio = cipher_bio;
	else if (!BIO_push(*pbio, cipher_bio)) {
		CPKerr(CPK_F_BIO_ADD_CIPHER, ERR_R_BIO_LIB);
		goto err;
	}
	cipher_bio = NULL;
	return 1;
err:
	if (cipher_bio) BIO_free(cipher_bio);
	return 0;
}


static BIO *CPK_PKCS7_find_digest(EVP_MD_CTX **pmd, BIO *bio, int nid)
{
	for (;;) {
		if ((bio = BIO_find_type(bio, BIO_TYPE_MD)) == NULL) {
			CPKerr(CPK_F_CPK_PKCS7_FIND_DIGEST,
				CPK_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
			return NULL;
		}
		
		BIO_get_md_ctx(bio,pmd);
		if (*pmd == NULL) {
			CPKerr(CPK_F_CPK_PKCS7_FIND_DIGEST,
				ERR_R_INTERNAL_ERROR);
			return NULL;
		}

		if (EVP_MD_CTX_type(*pmd) == nid)
			return bio;

		bio=BIO_next(bio);
	}
}

long CPK_PKCS7_ctrl(CPK_PKCS7 *p7, int cmd, long larg, char *parg)
{
	int nid;
	long ret;

	nid = OBJ_obj2nid(p7->type);

	switch (cmd) {
	case PKCS7_OP_SET_DETACHED_SIGNATURE:
		if (nid == NID_pkcs7_signed) {
			ret=p7->detached=(int)larg;
			if (ret && PKCS7_type_is_data(p7->d.sign->contents)) {
				ASN1_OCTET_STRING *os;
				os = p7->d.sign->contents->d.data;
				ASN1_OCTET_STRING_free(os);
				p7->d.sign->contents->d.data = NULL;
			}
		} else {
			//CPKerr(CPK_F_CPK_PKCS7_CTRL, PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE);
			ret=0;
		}
		break;
	case PKCS7_OP_GET_DETACHED_SIGNATURE:
		if (nid == NID_pkcs7_signed) {
			if(!p7->d.sign  || !p7->d.sign->contents->d.ptr)
				ret = 1;
			else ret = 0;
				
			p7->detached = ret;
		} else {
			//CPKerr(CPK_F_CPK_PKCS7_CTRL,PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE);
			ret=0;
		}	
		break;
	default:
		//CPKerr(CPK_F_CPK_PKCS7_CTRL,PKCS7_R_UNKNOWN_OPERATION);
		ret=0;
	}
	return(ret);
}

/**
 * this function must be called just after CPK_PKCS7_new()
 */
int CPK_PKCS7_set_type(CPK_PKCS7 *p7, int type)
{
	OPENSSL_assert(p7->d.data == NULL);

	p7->type = OBJ_nid2obj(type);

	switch (type) {
	case NID_pkcs7_signed:
		if (!(p7->d.sign = CPK_SIGNED_new())) {
			CPKerr(CPK_F_CPK_PKCS7_SET_TYPE, ERR_R_ASN1_LIB);
			goto err;
		}
		p7->d.sign->version = CPK_CMS_VERSION;
		break;
	case NID_pkcs7_data:
		if (!(p7->d.data = M_ASN1_OCTET_STRING_new())) {
			CPKerr(CPK_F_CPK_PKCS7_SET_TYPE, ERR_R_ASN1_LIB);
			goto err;
		}
		break;
	case NID_pkcs7_signedAndEnveloped:
		if (!(p7->d.signed_and_enveloped = CPK_SIGN_ENVELOPE_new())) {
			CPKerr(CPK_F_CPK_PKCS7_SET_TYPE, ERR_R_ASN1_LIB);
			goto err;
		}
		p7->d.signed_and_enveloped->version = CPK_CMS_VERSION;
		p7->d.signed_and_enveloped->enc_data->content_type
			= OBJ_nid2obj(NID_pkcs7_data);
		break;
	case NID_pkcs7_enveloped:
		if (!(p7->d.enveloped = CPK_ENVELOPE_new())) {
			CPKerr(CPK_F_CPK_PKCS7_SET_TYPE, ERR_R_ASN1_LIB);
			goto err;
		}
		p7->d.enveloped->version = CPK_CMS_VERSION;
		p7->d.enveloped->enc_data->content_type
			= OBJ_nid2obj(NID_pkcs7_data);
		break;
	default:
		CPKerr(CPK_F_CPK_PKCS7_SET_TYPE, CPK_R_UNKNOWN_PKCS7_TYPE);
		goto err;
	}
	
	return 1;
err:
	return 0;
}

int CPK_PKCS7_set_content(CPK_PKCS7 *p7, CPK_PKCS7 *p7_data)
{
	switch (OBJ_obj2nid(p7->type)) {
	case NID_pkcs7_signed:
		if (p7->d.sign->contents)
			CPK_PKCS7_free(p7->d.sign->contents);
		p7->d.sign->contents = p7_data;
		break;
	case NID_pkcs7_data:
	case NID_pkcs7_enveloped:
	case NID_pkcs7_signedAndEnveloped:
	case NID_pkcs7_encrypted:
	default:
		goto err;
	}

	return 1;
err:
	return 0;
}

int CPK_PKCS7_content_new(CPK_PKCS7 *p7, int type)
{
	CPK_PKCS7 *content = NULL;
	if (!(content = CPK_PKCS7_new())) {
		CPKerr(CPK_F_CPK_PKCS7_CONTENT_NEW, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!CPK_PKCS7_set_type(content, type)) {
		CPKerr(CPK_F_CPK_PKCS7_CONTENT_NEW, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!CPK_PKCS7_set_content(p7, content)) {
		CPKerr(CPK_F_CPK_PKCS7_CONTENT_NEW, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	return 1;
err:
	if (content) CPK_PKCS7_free(content);
	return 0;
}

int CPK_PKCS7_add_signer(CPK_PKCS7 *p7, const EVP_MD *sign_alg,
	const CPK_KEY_INFO *sign_key)
{
	int r = 0, i, nid;
	STACK_OF(X509_ALGOR) *md_sk = NULL;
	STACK_OF(CPK_SIGNER_INFO) *si_sk = NULL;
	CPK_SIGNER_INFO *si = NULL;
	X509_ALGOR *algor = NULL;
	int digest_added = 0;

	// this function must be called after CPK_PKCS7_set_type()
	OPENSSL_assert(p7->d.data);
	// current only support ECDSA with SHA1
	OPENSSL_assert(sign_alg == EVP_sha1());

	switch (OBJ_obj2nid(p7->type)) {
	case NID_pkcs7_signed:
		md_sk = p7->d.sign->digest_algors;
		si_sk = p7->d.sign->signer_infos;
		break;
	case NID_pkcs7_signedAndEnveloped:
		md_sk = p7->d.signed_and_enveloped->digest_algors;
		si_sk = p7->d.signed_and_enveloped->signer_infos;
		break;
	default:
		CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER, CPK_R_UNKNOWN_PKCS7_TYPE);
		goto err;
	}
	OPENSSL_assert(md_sk && si_sk);

	// create signer_info
	if (!(si = CPK_SIGNER_INFO_new())) {
		CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!CPK_SIGNER_INFO_set(si, sign_alg, sign_key)) {
		CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER, CPK_R_SET_SIGNER);
		goto err;
	}
	
	if (!(nid = EVP_MD_type(sign_alg))) {
		CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER, CPK_R_UNKNOWN_DIGEST_TYPE);
		goto err;
	}

	// push digest algor into pkcs7 stack
	for (i = 0; i < sk_X509_ALGOR_num(md_sk); i++) {
		algor = sk_X509_ALGOR_value(md_sk,i);
		if (OBJ_obj2nid(algor->algorithm) == nid) {
			digest_added = 1;
			break;
		}
	}
	if (!digest_added) {
		if (!(algor = X509_ALGOR_new())) {
			CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER,
				ERR_R_MALLOC_FAILURE);
			goto err;
		}
		algor->algorithm = OBJ_nid2obj(nid);
		if (!sk_X509_ALGOR_push(md_sk, algor)) {
			X509_ALGOR_free(algor);
			CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER, ERR_R_OBJ_LIB);
			goto err;
		}
	}

	if (!sk_push(si_sk,(char *)si)) {
		CPK_SIGNER_INFO_free(si);
		CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER, CPK_R_STACK_ERROR);
		goto err;
	}

	return 1;
err:
	return 0;
}

int CPK_PKCS7_add_recipient(CPK_PKCS7 *p7,
	const CPK_IDENTITY_INFO *id, const ECIES_PARAMS *params)
{
	CPK_RECIP_INFO *ri = NULL;
	STACK_OF(CPK_RECIP_INFO) *ri_sk = NULL;

	OPENSSL_assert(p7 && id && params);

	switch (OBJ_obj2nid(p7->type)) {
	case NID_pkcs7_enveloped:
		ri_sk = p7->d.enveloped->recip_infos;
		break;
	case NID_pkcs7_signedAndEnveloped:
		ri_sk = p7->d.signed_and_enveloped->recip_infos;
		break;
	default:
		CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER, 
			ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		goto err;
	}
	OPENSSL_assert(ri_sk);

	if ((ri = CPK_RECIP_INFO_new()) == NULL) {
		CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!CPK_RECIP_INFO_set(ri, id, params)) {
		CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER, CPK_R_SET_RECIP_INFO);
		goto err;
	}

	if (!sk_push(ri_sk, (char *)ri)) {
		CPKerr(CPK_F_CPK_PKCS7_ADD_SIGNER, CPK_R_STACK_ERROR);
		goto err;
	}

	return 1;
err:
	return 0;
}

int CPK_PKCS7_set_cipher(CPK_PKCS7 *p7, const EVP_CIPHER *cipher)
{
	int type = OBJ_obj2nid(p7->type);
	CPK_ENC_CONTENT *ec;

	// this function must be called after CPK_PKCS7_set_type()
	OPENSSL_assert(p7->d.data);

	switch (type) {
	case NID_pkcs7_signedAndEnveloped:
		ec = p7->d.signed_and_enveloped->enc_data;
		break;
	case NID_pkcs7_enveloped:
		ec = p7->d.enveloped->enc_data;
		break;
	default:
		CPKerr(CPK_F_CPK_PKCS7_SET_CIPHER, CPK_R_UNKNOWN_PKCS7_TYPE);
		return 0;
	}

	if(EVP_CIPHER_type(cipher) == NID_undef) {
		CPKerr(CPK_F_CPK_PKCS7_SET_CIPHER, CPK_R_BAD_ARGUMENT);
		return 0;
	}

	ec->cipher = cipher;
	return 1;
}

STACK_OF(CPK_SIGNER_INFO) *CPK_PKCS7_get_signer_infos(CPK_PKCS7 *p7)
{
	if (CPK_PKCS7_type_is_signed(p7))
		return(p7->d.sign->signer_infos);
	else if (CPK_PKCS7_type_is_signedAndEnveloped(p7))
		return(p7->d.signed_and_enveloped->signer_infos);
	else	return(NULL);
}

BIO *CPK_PKCS7_dataInit(CPK_PKCS7 *p7, BIO *bio)
{
	int i;
	BIO *out_bio = NULL;
	STACK_OF(X509_ALGOR) *md_sk = NULL;
	STACK_OF(CPK_RECIP_INFO) *ri_sk = NULL;
	X509_ALGOR *cipher_algor = NULL;
	const EVP_CIPHER *cipher = NULL;
	ASN1_OCTET_STRING *os = NULL;

	// prepare
	switch (OBJ_obj2nid(p7->type)) {
	case NID_pkcs7_signed:
		md_sk = p7->d.sign->digest_algors;
		os = p7->d.sign->contents->d.data;
		OPENSSL_assert(md_sk && sk_X509_ALGOR_num(md_sk) > 0);
		OPENSSL_assert(os);
		break;
	case NID_pkcs7_enveloped:
		ri_sk = p7->d.enveloped->recip_infos;
		cipher = p7->d.enveloped->enc_data->cipher;
		cipher_algor = p7->d.enveloped->enc_data->enc_algor;
		OPENSSL_assert(ri_sk && sk_num(ri_sk) > 0);
		OPENSSL_assert(cipher);
		break;
	case NID_pkcs7_signedAndEnveloped:
		md_sk = p7->d.signed_and_enveloped->digest_algors;
		ri_sk = p7->d.signed_and_enveloped->recip_infos;
		cipher = p7->d.signed_and_enveloped->enc_data->cipher;
		cipher_algor = p7->d.signed_and_enveloped->enc_data->enc_algor;
		OPENSSL_assert(md_sk && sk_X509_ALGOR_num(md_sk) > 0);
		OPENSSL_assert(ri_sk && sk_num(ri_sk) > 0);
		OPENSSL_assert(cipher);
		break;
	default:
		CPKerr(CPK_F_CPK_PKCS7_DATAINIT, CPK_R_UNKNOWN_PKCS7_TYPE);
	        goto err;
	}

	// add digest to bio
	for (i = 0; i < sk_X509_ALGOR_num(md_sk); i++) {
		X509_ALGOR *digest_algor = sk_X509_ALGOR_value(md_sk, i);
		if (!bio_add_digest(&out_bio, digest_algor)) {
			CPKerr(CPK_F_CPK_PKCS7_DATAINIT, ERR_R_CPK_LIB);
			goto err;
		}
	}

	// add cipher to bio
	if (cipher_algor) {
		CPK_RECIP_INFO *ri;
		unsigned char key[EVP_MAX_KEY_LENGTH];
		int keylen = EVP_CIPHER_key_length(cipher);

		if (RAND_pseudo_bytes(key, keylen) <= 0) {
			CPKerr(CPK_F_CPK_PKCS7_DATAINIT, ERR_R_RAND_LIB);
			goto err;
		}
		if (!bio_add_cipher(&out_bio, cipher_algor, cipher, key, 1)) {
			CPKerr(CPK_F_CPK_PKCS7_DATAINIT, ERR_R_CPK_LIB);
			goto err;
		}
		// create recipient_info
		for (i = 0; i < sk_num(ri_sk); i++) {
			ri = (CPK_RECIP_INFO *)sk_value(ri_sk, i);
			if (!CPK_RECIP_INFO_do_encrypt(ri, key, keylen)) {
				CPKerr(CPK_F_CPK_PKCS7_DATAINIT,
					ERR_R_CPK_LIB);
				goto err;
			}
		}
		OPENSSL_cleanse(key, keylen);
	}

	// append source/sink bio to bio chain
	if (bio == NULL) {
		if (CPK_PKCS7_is_detached(p7))
			bio = BIO_new(BIO_s_null());
		else if (os && os->length > 0)
			bio = BIO_new_mem_buf(os->data, os->length);

		if(bio == NULL) {
			if (!(bio = BIO_new(BIO_s_mem()))) {
				CPKerr(CPK_F_CPK_PKCS7_DATAINIT,
					ERR_R_BIO_LIB);
				goto err;
			}
			BIO_set_mem_eof_return(bio, 0);
		}
	}

	BIO_push(out_bio, bio);
	bio=NULL;
	return out_bio;
err:
	if (out_bio) BIO_free_all(out_bio);
	return NULL;
}

BIO *CPK_PKCS7_dataDecode(CPK_PKCS7 *p7, BIO *in_bio,
	const CPK_KEY_INFO *keyinfo)
{
	int i;
	BIO *out_bio = NULL, *bio = NULL;
	STACK_OF(X509_ALGOR) *md_sk = NULL;
	STACK_OF(CPK_RECIP_INFO) *ri_sk = NULL;
	X509_ALGOR *cipher_algor = NULL;
	const EVP_CIPHER *cipher = NULL;
	ASN1_OCTET_STRING *data_body = NULL;


	switch (OBJ_obj2nid(p7->type)) {
	case NID_pkcs7_signed:
		md_sk = p7->d.sign->digest_algors;
		data_body = p7->d.sign->contents->d.data;
		OPENSSL_assert(md_sk && sk_num(md_sk) > 0 && data_body);
		break;
	case NID_pkcs7_enveloped:
		ri_sk = p7->d.enveloped->recip_infos;
		cipher_algor = p7->d.enveloped->enc_data->enc_algor;
		data_body = p7->d.enveloped->enc_data->enc_data;
		OPENSSL_assert(ri_sk && sk_num(ri_sk) > 0);
		OPENSSL_assert(data_body);
		break;
	case NID_pkcs7_signedAndEnveloped:
		md_sk = p7->d.signed_and_enveloped->digest_algors;
		ri_sk = p7->d.signed_and_enveloped->recip_infos;
		cipher_algor = p7->d.signed_and_enveloped->enc_data->enc_algor;
		data_body = p7->d.signed_and_enveloped->enc_data->enc_data;
		OPENSSL_assert(md_sk && sk_X509_ALGOR_num(md_sk) > 0);
		OPENSSL_assert(ri_sk && sk_num(ri_sk) > 0);
		OPENSSL_assert(data_body);
		break;
	default:
		CPKerr(CPK_F_CPK_PKCS7_DATADECODE, CPK_R_UNKNOWN_PKCS7_TYPE);
	        goto err;
	}

	if (cipher_algor) {
		OPENSSL_assert(keyinfo);
		if (!(cipher = EVP_get_cipherbyobj(cipher_algor->algorithm))) {
			CPKerr(CPK_F_CPK_PKCS7_DATADECODE,
				CPK_R_UNKNOWN_CIPHER_TYPE);
			goto err;
		}
	}

	// append digest_bio to bio chain
	if (md_sk) {
		X509_ALGOR *algor;
		for (i = 0; i < sk_X509_ALGOR_num(md_sk); i++) {
			algor = sk_X509_ALGOR_value(md_sk, i);
			if (!bio_add_digest(&out_bio, algor)) {
				CPKerr(CPK_F_CPK_PKCS7_DATADECODE,
					ERR_R_CPK_LIB);
				goto err;
			}
		}
	}

	// append cipher_bio to bio chain
	if (cipher_algor) {
		// FIXME:
		// ECIES_do_decrypt will check buffer length
		// before decryption, it can not get a accurate
		// length of the decrypted key at that time,
		// so we need a much bigger buffer for key.
		unsigned char key[256];
		int keylen = sizeof(key);
		CPK_RECIP_INFO *ri = NULL;
		
		// check if the keyinfo can decrypt one of the ricip_infos
		for (i = 0; i < sk_num(ri_sk); i++) {
			ri = (CPK_RECIP_INFO *)sk_value(ri_sk, i);
			if (CPK_IDENTITY_INFO_cmp(
				ri->recipient, keyinfo->identity)==0) {
				break;
			}
			ri = NULL;
		}
		if (ri == NULL) {
			// the keyinfo cant decrypt any recip_info
			CPKerr(CPK_F_CPK_PKCS7_DATADECODE,
				CPK_R_WITHOUT_DECRYPT_KEY);
			goto err;
		}

		if (!CPK_RECIP_INFO_do_decrypt(ri, keyinfo, 
			key, (size_t *)&keylen)) {
			CPKerr(CPK_F_CPK_PKCS7_DATADECODE,
				ERR_R_CPK_LIB);
			goto err;
		}
		if (keylen != EVP_CIPHER_key_length(cipher)) {
			CPKerr(CPK_F_CPK_PKCS7_DATADECODE,
				ERR_R_CPK_LIB);
			goto err;
		}

		if (!bio_add_cipher(&out_bio, cipher_algor, cipher, key, 0)) {
			CPKerr(CPK_F_CPK_PKCS7_DATADECODE, ERR_R_CPK_LIB);
			goto err;
		}
	}

	// if pkcs7 is detached, create source bio from input
	// else init source bio by data_body
	if (CPK_PKCS7_is_detached(p7) || (in_bio != NULL)) {
		bio = in_bio;
	} else  {
		if (data_body->length > 0) {
			bio = BIO_new_mem_buf(data_body->data, 
				data_body->length);
		} else {
			bio = BIO_new(BIO_s_mem());
			BIO_set_mem_eof_return(bio, 0);
		}
		if (bio == NULL)
			goto err;
	}
	// append source_bio to bio chain
	BIO_push(out_bio, bio);
	bio = NULL;
	return out_bio;

err:
	if (out_bio) BIO_free_all(out_bio);
	return NULL;
}

int CPK_PKCS7_dataUpdate(CPK_PKCS7 *p7, BIO *bio,
	const unsigned char *data, int len)
{
	return BIO_write(bio, data, len);
}

int CPK_PKCS7_dataFinal(CPK_PKCS7 *p7, BIO *bio)
{
	int r = 0;
	STACK_OF(CPK_SIGNER_INFO) *si_sk = NULL;
	ASN1_OCTET_STRING *os = NULL;
	EVP_MD_CTX *ctx, tmp_ctx;

	EVP_MD_CTX_init(&tmp_ctx);
	BIO_flush(bio);

	/*
	 * prepare 
	 *   signer_info stack
	 *   encrypted data content	   	
	 */
	switch (OBJ_obj2nid(p7->type)) {
	case NID_pkcs7_signedAndEnveloped:
		si_sk = p7->d.signed_and_enveloped->signer_infos;
		if (!(os = M_ASN1_OCTET_STRING_new())) {
			CPKerr(CPK_F_CPK_PKCS7_DATAFINAL,ERR_R_MALLOC_FAILURE);
			goto err;
		}
		p7->d.signed_and_enveloped->enc_data->enc_data = os;
		break;
	case NID_pkcs7_enveloped:
		if (!(os = M_ASN1_OCTET_STRING_new())) {
			CPKerr(CPK_F_CPK_PKCS7_DATAFINAL,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		p7->d.enveloped->enc_data->enc_data = os;
		break;
	case NID_pkcs7_signed:
		si_sk = p7->d.sign->signer_infos;
		os = p7->d.sign->contents->d.data;
		/* If detached data then the content is excluded */
		if(PKCS7_type_is_data(p7->d.sign->contents) && p7->detached) {
			M_ASN1_OCTET_STRING_free(os);
			p7->d.sign->contents->d.data = NULL;
		}
		break;
	}

	if (si_sk) {
		int i, md_nid;
		CPK_SIGNER_INFO *si;
		for (i = 0; i < sk_num(si_sk); i++) {
			si = (CPK_SIGNER_INFO *)sk_value(si_sk, i);

			if (!(md_nid = OBJ_obj2nid(si->sign_algor->algorithm))) {
				goto err;
			}
			if (!CPK_PKCS7_find_digest(&ctx, bio, md_nid)) {
				goto err;
			}
			if (!EVP_MD_CTX_copy(&tmp_ctx, ctx)) {
				goto err;
			}
			if (!CPK_SIGNER_INFO_do_sign(si, &tmp_ctx)) {
				goto err;
			}
		}
	}

	if (!CPK_PKCS7_is_detached(p7)) {
		BIO *tmp_bio;
		BUF_MEM *buf_mem;

		if (!(tmp_bio = BIO_find_type(bio, BIO_TYPE_MEM))) {
			CPKerr(CPK_F_CPK_PKCS7_DATAFINAL, ERR_R_BIO_LIB);
			goto err;
		}
		BIO_get_mem_ptr(tmp_bio, &buf_mem);
		/* Mark the BIO read only then we can use its copy of the data
		 * instead of making an extra copy.
		 */
		BIO_set_flags(tmp_bio, BIO_FLAGS_MEM_RDONLY);
		BIO_set_mem_eof_return(tmp_bio, 0);
		os->data = (unsigned char *)buf_mem->data;
		os->length = buf_mem->length;
	}

	r = 1;
err:
	EVP_MD_CTX_cleanup(&tmp_ctx);
	return r;
}

int CPK_PKCS7_dataVerify(CPK_PUBLIC_MATRIX *public_matrix, BIO *bio,
	CPK_PKCS7 *p7, CPK_SIGNER_INFO *si)
{
	int r = 0, md_nid;
	EVP_MD_CTX *ctx = NULL;
	EVP_MD_CTX tmp_ctx;

	OPENSSL_assert(public_matrix && bio && p7 && si);
	OPENSSL_assert(CPK_PKCS7_type_is_signed(p7) ||
		CPK_PKCS7_type_is_signedAndEnveloped(p7));

	EVP_MD_CTX_init(&tmp_ctx);

	if (ASN1_STRING_cmp(public_matrix->matrix_uri, 
		si->signer->matrix_uri)) {
		CPKerr(CPK_F_CPK_PKCS7_DATAVERIFY, ERR_R_CPK_LIB);
		goto err;
	}
	if (!(md_nid = OBJ_obj2nid(si->digest_algor->algorithm))) {
		CPKerr(CPK_F_CPK_PKCS7_DATAVERIFY, ERR_R_CPK_LIB);
		goto err;
	}
	if (!CPK_PKCS7_find_digest(&ctx, bio, md_nid)) {
		CPKerr(CPK_F_CPK_PKCS7_DATAVERIFY, ERR_R_CPK_LIB);
		goto err;
	}
	EVP_MD_CTX_copy(&tmp_ctx, ctx);
	if (!CPK_SIGNER_INFO_do_verify(si, &tmp_ctx, public_matrix)) {
		CPKerr(CPK_F_CPK_PKCS7_DATAVERIFY, ERR_R_CPK_LIB);
		goto err;
	}

	r = 1;
err:
	EVP_MD_CTX_cleanup(&tmp_ctx);
	return r;
}
