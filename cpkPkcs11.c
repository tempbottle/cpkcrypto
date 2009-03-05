#include "cpkPkcs11.h"
#include "cpkGlobal.h"
#include "cpkObject.h"
#include "cpkSession.h"


#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include "pkcs11cpk.h"


#define CPK_MAX_SIGNER_INFO_LENGTH		4096
#define CPK_MAX_RECIP_INFO_LENGTH		4096


void cpk_init_library(void)
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_load_ECIES_strings();
	ERR_load_CPK_strings();
}

/*

 C_VerifyInit
 C_VerifyUpdate
 C_VerifyFinal
	For CPK_SIGNER_INFO signature, C_VerifyInit can not get the digest mechanism, 
	we can only get the digest mechanism until C_VerfyFinal with input pSignature.

	There are two solutions:
	1. Only support 

CKM_CPK_ECDSA
	only support C_Verify
	or a list of agreed mechanims, the lib will generate every the result of  permitted mech 

CKM_CPK_ECDSA_SHA1
	support C_VerifyUpdate, but may be fail because of the wrong digest mechanism.

*/


/* build a CPK_IDENTITY_INFO with CPK_PUBLIC_MATRIX 
 * from CKA_CPK_ID and CKA_CPK_DER
 */
CK_RV
cpk_build_public_key_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object)
{
	CK_RV rv;
	CPK_PUBLIC_MATRIX *public_matrix = NULL;
	CPK_IDENTITY_INFO *identity_info = NULL;
	unsigned char *der = NULL, *id = NULL;
	unsigned int derlen = 0, idlen = 0;
	const unsigned char *cp;
	CK_ULONG i;

	for (i = 0; i < ulAttrNum; i++) {
		switch (template[i].type) {
		case CKA_CLASS:
		case CKA_KEY_TYPE:
			break;
		case CKA_CPK_DER:
			der = template[i].pValue;
			derlen = template[i].ulValueLen;
			break;
		case CKA_CPK_ID:
			id = template[i].pValue;
			idlen = template[i].ulValueLen;
			break;
		default:
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}
	}

	if (der == NULL || derlen <= 0 || id == NULL || idlen <= 0)
		return (CKR_ATTRIBUTE_VALUE_INVALID);

	identity_info = CPK_IDENTITY_INFO_new();
	if (identity_info == NULL)
		return (CKR_HOST_MEMORY);

	cp = der;
	// FIXME: without add_all_algorthms, the d2i_XXX can also return
	// a non-null object, but with inner OID empth
	public_matrix = d2i_CPK_PUBLIC_MATRIX(NULL, &cp, derlen);
	if (public_matrix == NULL) {
		CPK_IDENTITY_INFO_free(identity_info);
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	rv = CPK_IDENTITY_INFO_set(identity_info, NULL, 0,
		id, idlen, public_matrix, NULL);
	if (rv != B_TRUE) {
		CPK_IDENTITY_INFO_free(identity_info);
		CPK_PUBLIC_MATRIX_free(public_matrix);
		return (CKR_FUNCTION_FAILED);
	}


	new_object->class = CKO_PUBLIC_KEY;
	new_object->key_type = CKK_CPK;
	new_object->object_u.identity_info = identity_info;

	return (CKR_OK);
}

CK_RV
cpk_build_signer_info_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object)
{
	CK_RV rv = CKR_OK;
	CPK_SIGNER_INFO *signer_info = NULL_PTR;
	CK_BYTE_PTR der = NULL_PTR;
	CK_ULONG derlen = 0;
	const unsigned char *cp;
	CK_ULONG i;

	for (i = 0; i < ulAttrNum; i++) {
		switch (template[i].type) {
		case CKA_CLASS:
		case CKA_DATA_TYPE:
			break;
		case CKA_CPK_DER:
			der = template[i].pValue;
			derlen = template[i].ulValueLen;
			break;
		default:
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}
	}

	if (der == NULL || derlen <= 0)
		return (CKR_ATTRIBUTE_VALUE_INVALID);



	cp = der;
	signer_info = d2i_CPK_SIGNER_INFO(NULL, &cp, derlen);
	if (signer_info == NULL) {
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	new_object->class = CKO_DATA;
	new_object->data_type = CKD_CPK_SIGNER_INFO;
	new_object->object_u.signer_info = signer_info;

	return (rv);
}

CK_RV
cpk_build_recip_info_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object)
{
	CK_RV rv = CKR_OK;
	CPK_RECIP_INFO *recip_info = NULL_PTR;
	CK_BYTE_PTR der = NULL_PTR;
	CK_ULONG derlen = 0;
	const unsigned char *cp;
	CK_ULONG i;

	for (i = 0; i < ulAttrNum; i++) {
		switch (template[i].type) {
		case CKA_CLASS:
		case CKA_KEY_TYPE:
			break;
		case CKA_CPK_DER:
			der = template[i].pValue;
			derlen = template[i].ulValueLen;
			break;
		default:
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}
	}

	if (der == NULL || derlen <= 0)
		return (CKR_ATTRIBUTE_VALUE_INVALID);



	cp = der;
	recip_info = d2i_CPK_RECIP_INFO(NULL, &cp, derlen);
	if (recip_info == NULL) {
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	new_object->class = CKO_DATA;
	new_object->key_type = CKD_CPK_RECIP_INFO;
	new_object->object_u.recip_info = recip_info;
	return (rv);
}

CK_RV
cpk_build_pkcs7_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object)
{
	CK_RV rv = CKR_OK;

	return (rv);
}


CK_RV
cpk_build_public_matrix_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object)
{
	CK_RV rv = CKR_OK;
	CPK_PUBLIC_MATRIX *public_matrix = NULL;
	unsigned char *der = NULL, *id = NULL;
	unsigned int derlen = 0, idlen = 0;
	const unsigned char *cp;
	CK_ULONG i;

	for (i = 0; i < ulAttrNum; i++) {
		switch (template[i].type) {
		case CKA_CLASS:
		case CKA_KEY_TYPE:
			break;
		case CKA_CPK_DER:
			der = template[i].pValue;
			derlen = template[i].ulValueLen;
			break;
		default:
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}
	}

	if (der == NULL || derlen <= 0)
		return (CKR_ATTRIBUTE_VALUE_INVALID);

	cp = der;
	// FIXME: without add_all_algorthms, the d2i_XXX can also return
	// a non-null object, but with inner OID empth
	public_matrix = d2i_CPK_PUBLIC_MATRIX(NULL, &cp, derlen);
	if (public_matrix == NULL) {
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	new_object->class = CKO_PUBLIC_KEY;
	new_object->key_type = CKK_CPK_MATRIX;
	new_object->object_u.public_matrix = public_matrix;

	return (CKR_OK);
}


CK_RV
cpk_build_private_key_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object)
{

	CPK_KEY_INFO *key_info = NULL;
	unsigned char *der = NULL;
	unsigned int derlen = 0;
	const unsigned char *cp;
	CK_ULONG i;

	for (i = 0; i < ulAttrNum; i++) {
		switch (template[i].type) {
		case CKA_CLASS:
		case CKA_KEY_TYPE:
			break;
		case CKA_CPK_DER:
			der = template[i].pValue;
			derlen = template[i].ulValueLen;
			break;
		default:
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}
	}

	if (der == NULL || derlen <= 0)
		return (CKR_ATTRIBUTE_VALUE_INVALID);

	cp = der;
	key_info = d2i_CPK_KEY_INFO(NULL, &cp, derlen);
	if (key_info == NULL) {
		CPK_KEY_INFO_free(key_info);
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	new_object->class = CKO_PRIVATE_KEY;
	new_object->key_type = CKK_CPK;
	new_object->object_u.key_info = key_info;

	return (CKR_OK);
}


void
cpk_cleanup_public_key_object(cpk_object_t *object_p)
{
	CPK_IDENTITY_INFO *identity_info = 
		object_p->object_u.identity_info;

	if (identity_info != NULL) {
		CPK_PUBLIC_MATRIX *public_matrix = 
			(CPK_PUBLIC_MATRIX *)identity_info->public_matrix;
		if (public_matrix)
			CPK_PUBLIC_MATRIX_free(public_matrix);
		CPK_IDENTITY_INFO_free(identity_info);
	}

	object_p->object_u.identity_info = NULL;
}


void
cpk_cleanup_private_key_object(cpk_object_t *object_p)
{
	if (object_p->object_u.key_info != NULL) {
		CPK_KEY_INFO_free(object_p->object_u.key_info);
		object_p->object_u.key_info = NULL;
	}
}

CK_RV
cpk_set_public_key_attribute(cpk_object_t *object_p,
	CK_ATTRIBUTE_PTR template, boolean_t copy)
{
	unsigned char *id = NULL;
	unsigned int idlen = 0;
	CK_RV rv;

	if (template->type == CKA_CPK_ID) {
		id = template->pValue;
		idlen = template->ulValueLen;
		rv = CPK_IDENTITY_INFO_set(object_p->object_u.identity_info,
			NULL, 0, id, idlen, NULL, NULL);
		if (rv != CPK_OK)
			return (CKR_FUNCTION_FAILED);
		return (CKR_OK);
	}

	return (CKR_ATTRIBUTE_TYPE_INVALID);
}


CK_RV
si_sign_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p)
{
	CK_RV rv;
	const EVP_MD *md = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	CPK_SIGNER_INFO *signer_info = NULL;
	CK_MECHANISM_TYPE digest_mech;


	/* check class and key_type of signing key*/
	if ((key_p->class != CKO_PRIVATE_KEY) ||
	    (key_p->key_type != CKK_CPK))
		return (CKR_KEY_TYPE_INCONSISTENT);


	/* Check to see if digest operation is already active */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	if (session_p->digest.flags & CRYPTO_OPERATION_ACTIVE) {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		return (CKR_OPERATION_ACTIVE);
	}
	session_p->digest.flags = CRYPTO_OPERATION_ACTIVE;
	(void) pthread_mutex_unlock(&session_p->session_mutex);


	/* convert signing mechanism to digest mechanism */
	switch (pMechanism->mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECDSA:
	case CKM_CPK_ECDSA_SHA1:
		digest_mech = CKM_SHA_1;
		md = EVP_sha1();
		break;
	default:
		return (CKR_MECHANISM_INVALID);
	}

	/* prepare digest context */
	md_ctx = EVP_MD_CTX_create();
	if (md_ctx == NULL) {
		rv = CKR_HOST_MEMORY;
		goto clean_exit;
	}
	if (!EVP_DigestInit(md_ctx, md)) {
		rv = CKR_GENERAL_ERROR;
		goto clean_exit;
	}

	/* prepare signing context */
	signer_info = CPK_SIGNER_INFO_new();
	if (signer_info == NULL) { 
		rv = CKR_HOST_MEMORY;
		goto clean_exit;
	}

	
	/* init signing context with digest algor and signing key */
	(void) pthread_mutex_lock(&key_p->object_mutex);
	rv = CPK_SIGNER_INFO_set(signer_info, md, key_p->object_u.key_info);
	if (rv != CPK_OK) {
		rv = CKR_GENERAL_ERROR;
		goto clean_exit;
	}
	(void) pthread_mutex_unlock(&key_p->object_mutex);


	/* add digest context and signing context to session */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->digest.flags = CRYPTO_OPERATION_ACTIVE;	
	session_p->digest.context = md_ctx;
	session_p->digest.mech.mechanism = digest_mech;
	session_p->sign.flags = CRYPTO_OPERATION_ACTIVE;
	session_p->sign.context = signer_info;
	session_p->sign.mech.mechanism = CKM_CPK_ECDSA_SHA1;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (CKR_OK);

clean_exit:
	if (md_ctx != NULL)
		EVP_MD_CTX_destroy(md_ctx);
	if (signer_info != NULL)
		CPK_SIGNER_INFO_free(signer_info);

	return rv;
}

CK_RV
si_verify_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p)
{
	CK_RV rv;
	const EVP_MD *md = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	CPK_SIGNER_INFO *signer_info = NULL;
	CK_MECHANISM_TYPE digest_mech = 0;

	if ((key_p->class != CKO_PUBLIC_KEY) ||
	    (key_p->key_type != CKK_CPK_MATRIX))
		return (CKR_KEY_TYPE_INCONSISTENT);

	/* from signing mech to digest mech */
	switch (pMechanism->mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECDSA:
		/* set the digest flag to be active 
		 * but with the digest context empty */
		/* without the knowledge of digest mech, we cant init */
		return (CKR_MECHANISM_INVALID);
	case CKM_CPK_ECDSA_SHA1:
		digest_mech = CKM_SHA_1;
		md = EVP_sha1();
		break;
	default:
		return (CKR_MECHANISM_INVALID);
	}

	/* prepare digest context */
	md_ctx = EVP_MD_CTX_create();
	if (md_ctx == NULL) {
		rv = CKR_HOST_MEMORY;
		goto clean_exit;
	}
	if (!EVP_DigestInit(md_ctx, md)) {
		rv = CKR_GENERAL_ERROR;
		goto clean_exit;
	}


	/* add digest context and signing context to session */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->digest.flags = CRYPTO_OPERATION_ACTIVE;	
	session_p->digest.context = md_ctx;
	session_p->digest.mech.mechanism = CKM_SHA_1;
	session_p->verify.flags = CRYPTO_OPERATION_ACTIVE;
	session_p->verify.context = key_p->object_u.public_matrix;
	session_p->verify.mech.mechanism = CKM_CPK_ECDSA_SHA1;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (CKR_OK);

clean_exit:
	if (md_ctx != NULL)
		EVP_MD_CTX_destroy(md_ctx);

	return rv;
}

/* the sign and verify flag has been checked by C_VerifyUpdate 
 * this functions without the need of session mutex for the 
 * sign verify context because the flags protect them */
CK_RV
si_sign_update(cpk_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	EVP_DigestUpdate((EVP_MD_CTX *)session_p->digest.context, pPart,
	    ulPartLen);

	return (CKR_OK);
}

CK_RV
si_verify_update(cpk_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	CK_MECHANISM_TYPE mechanism = session_p->sign.mech.mechanism;

	/* only with a specific digest mech may this func be run */
	switch (mechanism) {
	case CKM_CPK_ECDSA_SHA1:
		break;
	default:
		return (CKR_MECHANISM_INVALID);
	}

	EVP_DigestUpdate((EVP_MD_CTX *)session_p->digest.context, pPart,
	    ulPartLen);

	return (CKR_OK);
}


CK_RV
si_sign_final(cpk_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->sign.mech.mechanism;
	EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)session_p->digest.context;
	CPK_SIGNER_INFO *signer_info = (CPK_SIGNER_INFO *)session_p->sign.context;
	unsigned char *p;
	CK_RV rv = CKR_OK;

	if (pSignature == NULL) {
		*pulSignatureLen = CPK_MAX_SIGNER_INFO_LENGTH;
		rv = CKR_OK;
		goto clean1;
	}

	if (*pulSignatureLen < CPK_MAX_SIGNER_INFO_LENGTH) {
		*pulSignatureLen = CPK_MAX_SIGNER_INFO_LENGTH;
		rv = CKR_BUFFER_TOO_SMALL;
		goto clean1;
	}


	if (!CPK_SIGNER_INFO_add_signed_time(signer_info)) {
		rv = CKR_GENERAL_ERROR;
		goto err;
	}

	// FIXME: to error handling
	if (!CPK_SIGNER_INFO_add_signed_digest(signer_info, md_ctx)) {
		rv = CKR_GENERAL_ERROR;
		goto err;
	}

	if (!CPK_SIGNER_INFO_do_sign(signer_info, md_ctx)) {
		rv = CKR_GENERAL_ERROR;
		goto err;
	}

	p = pSignature;
	*pulSignatureLen = i2d_CPK_SIGNER_INFO(signer_info, &p);

err:
clean1:
	return rv;
}

CK_RV
si_sign(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv = CKR_OK;
	
	rv = si_sign_update(session_p, pData, ulDataLen);
	if (rv != CKR_OK)
		return (rv);
	
	rv = si_sign_final(session_p, pSignature, pulSignatureLen);
	return (rv);
}

CK_RV
si_verify(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{
	CK_RV rv = CKR_OK;

	rv = si_verify_update(session_p, pData, ulDataLen);
	if (rv != CKR_OK)
		return (rv);

	return si_verify_final(session_p, pSignature, ulSignatureLen);
}


/* set the digest flag to be zero, 
 * the cleanup will be done by cleanup functions*/
CK_RV
si_verify_final(cpk_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{


	CPK_SIGNER_INFO *signer_info = NULL;
	const unsigned char *cp = NULL;
	long len;
	CPK_PUBLIC_MATRIX *public_matrix;
	CK_RV rv = CKR_OK;
	EVP_MD_CTX *md_ctx = NULL;



	/* decode CPK_SIGNER_INFO object from input signature */
	cp = pSignature;
	len = (long)ulSignatureLen;
	signer_info = d2i_CPK_SIGNER_INFO(NULL, &cp, len);
	if (signer_info == NULL) {
		rv = CKR_GENERAL_ERROR;
		goto err;
	}

	md_ctx = (EVP_MD_CTX *)session_p->digest.context;
	
	public_matrix = (CPK_PUBLIC_MATRIX *)(session_p->verify.context);
	if (public_matrix == NULL) {
		rv = CKR_GENERAL_ERROR;
		goto err;
	}

	if (!CPK_SIGNER_INFO_do_verify(signer_info, md_ctx, public_matrix)) {
		rv = CKR_GENERAL_ERROR;
		goto err;
	}
	

err:
	return (rv);
}

/* to cleanup:
 * session_p->digest.context	EVP_MD_CTX
 * session_p->sign.context	CPK_SIGNER_INFO
 * session_p->verify.context	CPK_KEY_INFO
 */
void
si_sign_verify_cleanup(cpk_session_t *session_p, boolean_t sign)
{

	crypto_active_op_t *active_op;
	active_op = (sign) ? &(session_p->sign) : &(session_p->verify);

	if (session_p->digest.context != NULL) {
		EVP_MD_CTX_destroy((EVP_MD_CTX *)session_p->digest.context);
		session_p->digest.context = NULL;
		session_p->digest.flags = 0;
	}
	if (active_op->context != NULL) {
		if (sign)
			CPK_SIGNER_INFO_free((CPK_SIGNER_INFO *)active_op->context);
		else 
			CPK_PUBLIC_MATRIX_free((CPK_PUBLIC_MATRIX *)active_op->context);

		active_op->context = NULL;
	}
}

CK_RV
ri_encrypt_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
	cpk_object_t *key_p)
{
	CK_RV rv;

	ECIES_PARAMS ecies_params;
	CPK_RECIP_INFO *recip_info = NULL;
	CPK_IDENTITY_INFO *recip_id = NULL;

	switch (pMechanism->mechanism) {
	case CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_MD5HMAC:
		ecies_params.is_cofactor_dh = 0;
		ecies_params.dh_kdf_md = EVP_sha1();
		ecies_params.enc_cipher = EVP_des_ede3_cbc();
		ecies_params.enc_mac_md = EVP_md5();
		break;
	case CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CBC_PAD_SHA1HMAC:
		ecies_params.is_cofactor_dh = 0;
		ecies_params.dh_kdf_md = EVP_sha1();
		ecies_params.enc_cipher = EVP_aes_128_cbc();
		ecies_params.enc_mac_md = EVP_sha1();
		break;
	case CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CFB_SHA1HMAC:
		ecies_params.is_cofactor_dh = 0;
		ecies_params.dh_kdf_md = EVP_sha1();
		ecies_params.enc_cipher = EVP_aes_128_cfb();
		ecies_params.enc_mac_md = EVP_sha1();
		break;
	default:
		return (CKR_MECHANISM_INVALID);
	}

	recip_info = CPK_RECIP_INFO_new();
	if (recip_info == NULL)
		return (CKR_HOST_MEMORY);


	(void) pthread_mutex_lock(&key_p->object_mutex);
	recip_id = key_p->object_u.identity_info;
	rv = CPK_RECIP_INFO_set(recip_info, recip_id, &ecies_params);
	if (rv != CPK_OK) {
		(void) pthread_mutex_unlock(&key_p->object_mutex);
		CPK_RECIP_INFO_free(recip_info);
		return (CKR_GENERAL_ERROR);
	}
	(void) pthread_mutex_unlock(&key_p->object_mutex);


	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->encrypt.context = recip_info;
	session_p->encrypt.mech.mechanism = pMechanism->mechanism;
	(void) pthread_mutex_unlock(&session_p->session_mutex);


	return (CKR_OK);
}

CK_RV
ri_encrypt(cpk_session_t *session_p, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncrypted, CK_ULONG_PTR pulEncryptedLen)
{
	CK_RV rv;
	unsigned char *p;
	CPK_RECIP_INFO *recip_info = NULL;


	if (pEncrypted == NULL) {
		*pulEncryptedLen = ulDataLen + 2048;
		return (CKR_OK);
	}
	if (*pulEncryptedLen < ulDataLen + 2048) {
		*pulEncryptedLen = ulDataLen + 2048;
		return (CKR_BUFFER_TOO_SMALL);
	}


	// FIXME: mutex
	recip_info = session_p->encrypt.context;
	rv = CPK_RECIP_INFO_do_encrypt(recip_info, pData, ulDataLen);
	if (rv != CPK_OK) {
		ERR_load_crypto_strings();
		ERR_load_ECIES_strings();
		ERR_load_CPK_strings();
		ERR_print_errors_fp(stderr);
		return (CKR_GENERAL_ERROR);
	}

	p = pEncrypted;
	*pulEncryptedLen = i2d_CPK_RECIP_INFO(recip_info, &p);

	return (CKR_OK);
}


CK_RV
ri_decrypt_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p)
{
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->decrypt.context = key_p->object_u.key_info;
	session_p->decrypt.mech.mechanism = pMechanism->mechanism;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (CKR_OK);
}

CK_RV
ri_decrypt(cpk_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen)
{
	CK_RV rv = CKR_OK;
	CPK_KEY_INFO *key_info = (CPK_KEY_INFO *)session_p->decrypt.context;
	CPK_RECIP_INFO *recip_info = NULL;
	const unsigned char *cp;


	if (pData == NULL) {
		*pulDataLen = ulEncryptedDataLen;
		return (CKR_OK);
	}
	if (*pulDataLen < ulEncryptedDataLen) {
		*pulDataLen = ulEncryptedDataLen;
		return (CKR_BUFFER_TOO_SMALL);
	}

	cp = pEncryptedData;
	recip_info = d2i_CPK_RECIP_INFO(NULL, &cp, ulEncryptedDataLen);
	if (recip_info == NULL)
		return (CKR_GENERAL_ERROR);

	if (!CPK_RECIP_INFO_do_decrypt(recip_info, key_info,
		pData, (size_t *)pulDataLen)) {
		rv = CKR_GENERAL_ERROR;
	}

	CPK_RECIP_INFO_free(recip_info);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->decrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

#if 0

/*
 * for pkcs7 signed_and_enveloped, the init can be separated by 
 * C_SignInit and C_EncryptInit, Before the first C_EncryptUpdate,
 * C_SignUpdate or C_SignEncryptUpdate we do not know the type of
 * pkcs7, unless a specification of an accurrate pkcs7 type 
 */
CK_RV
p7_sign_recover_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p)
{

	
	switch (pMechanism->mechanism) {
	case CKM_CPK_PKCS7:
		break;
	default:
		return 0;
	}

	/* if sign flag not setted, set the flag */

	/* if p7 not inited */
	p7 = CPK_PKCS7_new();
	rv = CPK_PKCS7_set_type(p7, NID_pkcs7_signedAndEnvelped);
	rv = CPK_PKCS7_add_signer(p7, md, key_p->object_u.key_info);
}

CK_RV
p7_encrypt_recover_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
	cpk_object_t *key_p)
{


	/* if sign flag not setted, set the flag */

	p7 = CPK_PKCS7_new();
	rv = CPK_PKCS7_set_type(p7, NID_pkcs7_signedAndEnveloped);

	rv = CPK_PKCS7_add_recipient(p7, key_p->object_u.identity_info, &ecies_params);
}

CK_RV
p7_sign_recover(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{

	return CKR_OK;
}

/*

To Decrypt and verify a PKCS7 message, cpk api needs to:
	1. decode a PKCS7 DER message by d2i_CPK_PKCS7
	2. decrypt the message by CPK_PKCS7_dataDecode(p7, key_info)
	3. verify every SignerInfo by CPK_PKCS7_dataVerify(p7, public_matrix)

*/


/* we need the hKey (public matrix) to verify the signature 
 * add the public_matrix to verify.context
 *
 * the key_info from key_p must be preserved.
 */
CK_RV
p7_verify_recover_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p)
{
	return CKR_OK;
}


CK_RV
p7_verify_recover(cpk_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{

	const unsigned char *cp = pSignature;
	long maxlen = (long)ulSigantureLen;


	p7 = d2i_CPK_PKCS7(NULL, &cp, maxlen);


	key_info = (CPK_KEY_INFO *)session_p->decrypt.context;

	bio = CPK_PKCS7_dataDecode(p7, NULL, key_info);

	CPK_PKCS7_dataFinal(p7, bio);


}

#endif
