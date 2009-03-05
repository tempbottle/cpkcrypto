/* Copyright (c) 2007  "Guan Zhi" <guanzhi1980@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ecdh.h>
#include "ecies.h"


ECIES_CIPHERTEXT_VALUE *ECIES_do_encrypt(const ECIES_PARAMS *param,
	const unsigned char *in, size_t inlen, const EC_KEY *pub_key)
{
	int e = 1;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	EC_KEY *ephem_key = NULL;
	ECIES_CIPHERTEXT *ct = NULL;
	ECIES_MACTAG *mt = NULL;
	int len;

	unsigned char share[EVP_MAX_KEY_LENGTH + EVP_MAX_MD_SIZE];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char *enckey, *mackey, *p;
	int enckeylen, mackeylen;

	EVP_CIPHER_CTX cipher_ctx;
	EVP_CIPHER_CTX_init(&cipher_ctx);

	OPENSSL_assert(param && in && pub_key);
	OPENSSL_assert(param->enc_cipher);
	OPENSSL_assert(param->enc_mac_md);
	OPENSSL_assert(param->dh_kdf_md);

	if (!(cv = ECIES_CIPHERTEXT_VALUE_new())) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	// gen ephem_point
	if (!(ephem_key = EC_KEY_new())) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_KEY_set_group(ephem_key, EC_KEY_get0_group(pub_key))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto err;
	}
	if (!EC_KEY_generate_key(ephem_key)) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto err;
	}

	// encode ephem_point
	cv->ephem_point->length = (int)EC_POINT_point2oct(
		EC_KEY_get0_group(ephem_key),
		EC_KEY_get0_public_key(ephem_key), 
		POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
	if (!(cv->ephem_point->data = (unsigned char *)
		OPENSSL_malloc(cv->ephem_point->length))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	EC_POINT_point2oct(EC_KEY_get0_group(ephem_key),
		EC_KEY_get0_public_key(ephem_key), POINT_CONVERSION_COMPRESSED,
		cv->ephem_point->data, cv->ephem_point->length, NULL);

	// ecdh, get enckey and mackey
	enckeylen = EVP_CIPHER_key_length(param->enc_cipher);
	mackeylen = EVP_MD_size(param->enc_mac_md);
	if (!ECDH_compute_key(share, enckeylen + mackeylen, 
		EC_KEY_get0_public_key(pub_key), ephem_key,
		x963_kdf_from_md(param->dh_kdf_md))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ECIES_R_ECDH_FAILED);
		goto err;
	}

	enckey = share;
	mackey = share + enckeylen;

	// encrypt
	if (!(ct = ECIES_CIPHERTEXT_new())) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!(ct->algor->algorithm = OBJ_nid2obj(
		EVP_CIPHER_type(param->enc_cipher)))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, 
			ECIES_R_UNKNOWN_CIPHER_TYPE);
		goto err;
	}

	len = (int)(inlen + EVP_MAX_BLOCK_LENGTH * 2);
	if (!(ct->encdata->data = (unsigned char *)OPENSSL_malloc(len))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!RAND_pseudo_bytes(iv, EVP_CIPHER_iv_length(param->enc_cipher))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_RAND_LIB);
		goto err;
	}
	if (!EVP_EncryptInit(&cipher_ctx, param->enc_cipher, enckey, iv)) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ECIES_R_ENCRYPT_FAILED);
		goto err;
	}
	p = ct->encdata->data;
	if (!EVP_EncryptUpdate(&cipher_ctx, p, &len, in, (int)inlen)) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ECIES_R_ENCRYPT_FAILED);
		goto err;
	}
	p += len;
	if (!EVP_EncryptFinal(&cipher_ctx, p, &len)) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ECIES_R_ENCRYPT_FAILED);
		goto err;
	}
	p += len;
	ct->encdata->length = (int)(p - ct->encdata->data);
	if (!(ct->algor->parameter = ASN1_TYPE_new())) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EVP_CIPHER_set_asn1_iv(&cipher_ctx, ct->algor->parameter)) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_ASN1_LIB);
		goto err;
	}

	// encode ciphertext
	cv->ciphertext->length = i2d_ECIES_CIPHERTEXT(ct, NULL);
	if (!(cv->ciphertext->data = (unsigned char *)OPENSSL_malloc(
		cv->ciphertext->length))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	p = cv->ciphertext->data;
	i2d_ECIES_CIPHERTEXT(ct, &p);

	// gen mac
	if (!(mt = ECIES_MACTAG_new())) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}	
	if (!(mt->algor->algorithm = OBJ_nid2obj(
		EVP_MD_type(param->enc_mac_md)))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ECIES_R_UNKNOWN_MAC_TYPE);
		goto err;
	}
	mt->macdata->length = EVP_MD_size(param->enc_mac_md);
	if (!(mt->macdata->data = (unsigned char *)
		OPENSSL_malloc(mt->macdata->length))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	
	if (!HMAC(param->enc_mac_md, mackey, mackeylen, cv->ciphertext->data, 
		(size_t)cv->ciphertext->length, mt->macdata->data, &len)) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ECIES_R_GEN_MAC_FAILED);
		goto err;
	}

	// encode mac
	cv->mactag->length = i2d_ECIES_MACTAG(mt, NULL);
	if (!(cv->mactag->data = (unsigned char *)
		OPENSSL_malloc(cv->mactag->length))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	p = cv->mactag->data;
	i2d_ECIES_MACTAG(mt, &p);

	e = 0;
err:
	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	if (ephem_key) EC_KEY_free(ephem_key);
	if (ct) ECIES_CIPHERTEXT_free(ct);
	if (mt) ECIES_MACTAG_free(mt);	
	if (e && cv) {
		ECIES_CIPHERTEXT_VALUE_free(cv);
		cv = NULL;
	}

	return cv;
}

int ECIES_do_decrypt(const ECIES_CIPHERTEXT_VALUE *cv,
	ECIES_PARAMS *param, unsigned char *out, size_t *outlen, 
	const EC_KEY *sec_key)
{
	int r = 0;

	EC_KEY *ecdh = NULL;
	EC_POINT *ephem_pt = NULL;
	ECIES_CIPHERTEXT *ct = NULL;
	ECIES_MACTAG *mt = NULL;
	unsigned char share[EVP_MAX_KEY_LENGTH + EVP_MAX_MD_SIZE];
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned char *enckey, *mackey;
	int enckeylen, mackeylen, maclen, len;

	const unsigned char *cp;
	unsigned char *p;

	const EVP_CIPHER *cipher = NULL;
	const EVP_MD *mac_md = NULL;
	EVP_CIPHER_CTX cipher_ctx;

	// check output buffer size
	if (out == NULL) {
		*outlen = cv->ciphertext->length;
		return 1;
	}
	if ((int)(*outlen) < cv->ciphertext->length) {
		*outlen = cv->ciphertext->length;
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BUFFER_TOO_SMALL);
		return 0;
	}

	EVP_CIPHER_CTX_init(&cipher_ctx);

	// get ephem_point
	if (!cv->ephem_point || !cv->ephem_point->data) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BAD_DATA);
		goto err;
	}
	if (!(ephem_pt = EC_POINT_new(EC_KEY_get0_group(sec_key)))) {
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_POINT_oct2point(EC_KEY_get0_group(sec_key), ephem_pt,
		cv->ephem_point->data, cv->ephem_point->length, NULL)) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BAD_DATA);
		goto err;
	}

	// get cipher from ciphertext
	if (!cv->ciphertext || !cv->ciphertext->data) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BAD_DATA);
		goto err;
	}
	cp = cv->ciphertext->data;
	if (!(ct = d2i_ECIES_CIPHERTEXT(NULL, &cp, cv->ciphertext->length))) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BAD_DATA);
		goto err;
	}
	if (!(cipher = EVP_get_cipherbyobj(ct->algor->algorithm))) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, 
			ECIES_R_UNKNOWN_CIPHER_TYPE);
		goto err;
	}
	
	// get mac_md
	if (!cv->mactag || !cv->mactag->data) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BAD_DATA);
		goto err;
	}
	cp = cv->mactag->data;
	if (!(mt = d2i_ECIES_MACTAG(NULL, &cp, cv->mactag->length))) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BAD_DATA);
		goto err;
	}
	if (!(mac_md = EVP_get_digestbyobj(mt->algor->algorithm))) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_UNKNOWN_MAC_TYPE);
		goto err;
	}

	// ecdh, get enckey and mackey
	enckeylen = EVP_CIPHER_key_length(cipher);
	mackeylen = EVP_MD_size(mac_md);
	if (!(ecdh = EC_KEY_dup(sec_key))) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ERR_R_EC_LIB);
		goto err;
	}
	if (!ECDH_compute_key(share, enckeylen + mackeylen, ephem_pt,
		ecdh, x963_kdf_from_md(param->dh_kdf_md))) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_ECDH_FAILED);
		goto err;
	}
	enckey = share;
	mackey = share + enckeylen;

	// verify mac
	if (!HMAC(mac_md, mackey, mackeylen, cv->ciphertext->data,
		cv->ciphertext->length, mac, &maclen)) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_GEN_MAC_FAILED);
		goto err;
	}
	if (maclen != mt->macdata->length) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_VERIFY_MAC_FAILED);
		goto err;
	}
	if (memcmp(mac, mt->macdata->data, maclen) != 0) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_VERIFY_MAC_FAILED);
		goto err;
	}

	// decrypt
	if (!EVP_DecryptInit(&cipher_ctx, cipher, enckey, NULL)) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_DECRYPT_FAILED);
		goto err;
	}
	if (!EVP_CIPHER_get_asn1_iv(&cipher_ctx, ct->algor->parameter)) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_DECRYPT_FAILED);
		goto err;
	}
	p = out;
	if (!EVP_DecryptUpdate(&cipher_ctx, p, &len, ct->encdata->data, 
		ct->encdata->length)) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_DECRYPT_FAILED);
		goto err;
	}
	p += len;
	if (!EVP_DecryptFinal(&cipher_ctx, p, &len)) {
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_DECRYPT_FAILED);
		goto err;
	}	
	p += len;

	*outlen = (int)(p - out);
	
	r = 1;
err:
	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	if (ephem_pt) EC_POINT_free(ephem_pt);
	if (ct) ECIES_CIPHERTEXT_free(ct);
	if (mt) ECIES_MACTAG_free(mt);
	if (ecdh) EC_KEY_free(ecdh);

	return r;
}
