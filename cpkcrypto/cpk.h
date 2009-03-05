/*****************************************************************
 * CPK Crypto Library
 *
 * Author      : "Guan Zhi" <guanzhi1980@gmail.com>
 * Version     : 0.7
 * From	       : 2007-07-21
 * Last Update : 2007-08-20
 * Last Update : 
 *****************************************************************/

#ifndef HEADER_CPK_H
#define HEADER_CPK_H

#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>

#include "ecies.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define CPK_LIB_VERSION		"0.7.2"
#define CPK_CMS_VERSION		4
#define CPK_PKCS7_VERSION	CPK_CMS_VERSION
	
#define CPK_MAX_ID_LENGTH	255
#define CPK_MAX_COLUMN_SIZE	4096
#define CPK_MAX_ROW_SIZE	1024



typedef struct cpk_secret_matrix_st {
	long				 version;
	ASN1_UTF8STRING			*matrix_uri;
	ASN1_OBJECT			*curve_obj;
	X509_ALGOR			*map_algor;
	long				 column_size;
	long				 row_size;
	ASN1_OCTET_STRING		*bignums;
} CPK_SECRET_MATRIX;
DECLARE_ASN1_FUNCTIONS(CPK_SECRET_MATRIX)

typedef struct cpk_public_matrix_st {
	long				 version;
	ASN1_UTF8STRING			*matrix_uri;
	ASN1_OBJECT			*curve_obj;
	X509_ALGOR			*map_algor;
	long				 column_size;
	long				 row_size;
	ASN1_OCTET_STRING		*points;
} CPK_PUBLIC_MATRIX;
DECLARE_ASN1_FUNCTIONS(CPK_PUBLIC_MATRIX)

typedef struct cpk_identity_info_st {
	ASN1_UTF8STRING			*matrix_uri;
	ASN1_OBJECT			*id_schema;
	ASN1_OCTET_STRING		*id_data;
	/* private */
	const CPK_PUBLIC_MATRIX		*public_matrix;
	const EC_KEY			*public_key;
} CPK_IDENTITY_INFO;
DECLARE_ASN1_FUNCTIONS(CPK_IDENTITY_INFO)

typedef struct cpk_key_info_st {
	long				 version;
	CPK_IDENTITY_INFO		*identity;
	ASN1_OCTET_STRING		*key_data;
	ASN1_OBJECT			*curve_obj;
	/* private */
	const EC_KEY			*ec_key;
} CPK_KEY_INFO;
DECLARE_ASN1_FUNCTIONS(CPK_KEY_INFO)

typedef struct cpk_signer_info_st {
	long				 version;
	CPK_IDENTITY_INFO		*signer;
	X509_ALGOR			*digest_algor;
	STACK_OF(X509_ATTRIBUTE)	*auth_attr;
	X509_ALGOR			*sign_algor;
	ASN1_OCTET_STRING		*signature;
	STACK_OF(X509_ATTRIBTE)		*unauth_attr;	
	/* private */
	const CPK_KEY_INFO		*sign_key;
} CPK_SIGNER_INFO;
DECLARE_STACK_OF(CPK_SIGNER_INFO)
DECLARE_ASN1_SET_OF(CPK_SIGNER_INFO)
DECLARE_ASN1_FUNCTIONS(CPK_SIGNER_INFO)

typedef struct cpk_recip_info_st {
	long				 version;
	CPK_IDENTITY_INFO		*recipient;
	X509_ALGOR			*enc_algor;
	ASN1_OCTET_STRING		*enc_data;
	/* private */
	ECIES_PARAMS			 enc_params;
} CPK_RECIP_INFO;
DECLARE_STACK_OF(CPK_RECIP_INFO)
DECLARE_ASN1_SET_OF(CPK_RECIP_INFO)
DECLARE_ASN1_FUNCTIONS(CPK_RECIP_INFO)

typedef struct cpk_signed_st {
	long				 version;
	STACK_OF(X509_ALGOR)		*digest_algors;
	STACK_OF(X509)			*cert;	/* [ 0 ] */
	STACK_OF(X509_CRL)		*crl;	/* [ 1 ] */
	STACK_OF(CPK_SIGINFO)		*signer_infos;
	struct cpk_pkcs7_st		*contents;
} CPK_SIGNED;
DECLARE_ASN1_FUNCTIONS(CPK_SIGNED)

typedef struct cpk_enc_content_st {
	ASN1_OBJECT			*content_type;
	X509_ALGOR			*enc_algor;
	ASN1_OCTET_STRING		*enc_data;	/* [ 0 ] */
	/* private */
	const EVP_CIPHER		*cipher;
} CPK_ENC_CONTENT;
DECLARE_ASN1_FUNCTIONS(CPK_ENC_CONTENT)

typedef struct cpk_envelope_st {
	long				 version;
	STACK_OF(CPK_RECIP_INFO)	*recip_infos;
	CPK_ENC_CONTENT			*enc_data;
} CPK_ENVELOPE;
DECLARE_ASN1_FUNCTIONS(CPK_ENVELOPE)

typedef struct cpk_sign_envelope_st {
	long				 version;
	STACK_OF(X509_ALGOR)		*digest_algors;
	STACK_OF(X509)			*cert;	/* [ 0 ] */
	STACK_OF(X509_CRL)		*crl;	/* [ 1 ] */
	STACK_OF(CPK_SIGNER_INFO)	*signer_infos;
	CPK_ENC_CONTENT			*enc_data;
	STACK_OF(CPK_RECIP_INFO)	*recip_infos;
} CPK_SIGN_ENVELOPE;
DECLARE_ASN1_FUNCTIONS(CPK_SIGN_ENVELOPE)

typedef struct cpk_pkcs7_st {
	int state; /* used during processing */
	int detached;

	ASN1_OBJECT *type;
	union	{
		char *ptr;

		/* NID_pkcs7_data */
		ASN1_OCTET_STRING *data;

		/* NID_pkcs7_signed */
		CPK_SIGNED *sign;

		/* NID_pkcs7_enveloped */
		CPK_ENVELOPE *enveloped;

		/* NID_pkcs7_signedAndEnveloped */
		CPK_SIGN_ENVELOPE *signed_and_enveloped;

		/* Anything else */
		ASN1_TYPE *other;
	} d;
} CPK_PKCS7;
DECLARE_STACK_OF(CPK_PKCS7)
DECLARE_ASN1_SET_OF(CPK_PKCS7)
DECLARE_PKCS12_STACK_OF(CPK_PKCS7)
DECLARE_ASN1_FUNCTIONS(CPK_PKCS7)

DECLARE_ASN1_ITEM(CPK_PKCS7_ATTR_SIGN)
DECLARE_ASN1_ITEM(CPK_PKCS7_ATTR_VERIFY)
DECLARE_ASN1_NDEF_FUNCTION(CPK_PKCS7)


/* cpk_lib.c */

CPK_SECRET_MATRIX *CPK_SECRET_MATRIX_create(
	const char *matrix_uri, const char *curve_name,
	const EVP_MD *map_md, unsigned int column_size,
	unsigned int row_size, void *rand_param);

// public matrix
CPK_PUBLIC_MATRIX *CPK_PUBLIC_MATRIX_create(
	const CPK_SECRET_MATRIX *msk, int pt_compressed);
EC_KEY *CPK_PUBLIC_MATRIX_get_key(const CPK_PUBLIC_MATRIX *mpk,
	const CPK_IDENTITY_INFO *id);

/* CPK_IDENTITY_INFO */
int CPK_IDENTITY_INFO_set(CPK_IDENTITY_INFO *id,
	ASN1_UTF8STRING *matrix_uri, int id_schema,
	const char *id_data, size_t id_data_len,
	const CPK_PUBLIC_MATRIX *public_matrix, const EC_KEY *ec_key);
int CPK_IDENTITY_INFO_cmp(const CPK_IDENTITY_INFO *id,
	const CPK_IDENTITY_INFO *id2);
EC_KEY *CPK_IDENTITY_INFO_get_key(const CPK_IDENTITY_INFO *id);
#define CPK_IDENTITY_INFO_get0_key(id)	((id)->public_key)
#define CPK_IDENTITY_INFO_set0_key(id,ec_key) \
	do { (id)->public_key = ec_key; } while (0)

/** CPK_KEY_INFO */
CPK_KEY_INFO *CPK_KEY_INFO_create(const CPK_SECRET_MATRIX *msk,
	const CPK_IDENTITY_INFO *id);
EC_KEY *CPK_KEY_INFO_get_key(const CPK_KEY_INFO *ki);
#define CPK_KEY_INFO_set0_key(ki,ec_key) \
	do { (ki)->ec_key = ec_key; } while (0)
#define CPK_KEY_INFO_get0_key(ki) ((ki)->ec_key)


// signer info
int CPK_SIGNER_INFO_set(CPK_SIGNER_INFO *si,
	const EVP_MD *sign_alg, const CPK_KEY_INFO *sign_key);
int CPK_SIGNER_INFO_add_attr(CPK_SIGNER_INFO *si,
	int nid, int atrtype, void *value);
int CPK_SIGNER_INFO_add_signed_attr(CPK_SIGNER_INFO *si,
	int nid, int atrtype, void *value);
int CPK_SIGNER_INFO_add_signed_time(CPK_SIGNER_INFO *si);
int CPK_SIGNER_INFO_add_signed_digest(CPK_SIGNER_INFO *si,
	const EVP_MD_CTX *ctx);
int CPK_SIGNER_INFO_do_sign(CPK_SIGNER_INFO *si, EVP_MD_CTX *md_ctx);
ASN1_TYPE *CPK_SIGNER_INFO_get_attr(CPK_SIGNER_INFO *si, int nid);
ASN1_TYPE *CPK_SIGNER_INFO_get_signed_attr(CPK_SIGNER_INFO *si, int nid);
ASN1_UTCTIME *CPK_SIGNER_INFO_get_signed_time(CPK_SIGNER_INFO *si);
int CPK_SIGNER_INFO_do_verify(const CPK_SIGNER_INFO *si, EVP_MD_CTX *ctx,
	const CPK_PUBLIC_MATRIX *mpk);

// recip_info
int CPK_RECIP_INFO_set(CPK_RECIP_INFO *ri,
	const CPK_IDENTITY_INFO *recipient, const ECIES_PARAMS *params);
int CPK_RECIP_INFO_do_encrypt(CPK_RECIP_INFO *ri, 
	const unsigned char *in, size_t inlen);
int CPK_RECIP_INFO_do_decrypt(CPK_RECIP_INFO *ri,
	const CPK_KEY_INFO *ki, unsigned char *out, size_t *outlen);


#define CPK_PKCS7_OP_SET_DETACHED_SIGNATURE	1
#define CPK_PKCS7_OP_GET_DETACHED_SIGNATURE	2

#define CPK_PKCS7_get_signed_attributes(si)	((si)->auth_attr)
#define CPK_PKCS7_get_attributes(si)		((si)->unauth_attr)

#define CPK_PKCS7_type_is_signed(a)			\
	(OBJ_obj2nid((a)->type) == NID_pkcs7_signed)
#define CPK_PKCS7_type_is_enveloped(a)			\
	(OBJ_obj2nid((a)->type) == NID_pkcs7_enveloped)
#define CPK_PKCS7_type_is_signedAndEnveloped(a)		\
	(OBJ_obj2nid((a)->type) == NID_pkcs7_signedAndEnveloped)
#define CPK_PKCS7_type_is_data(a)			\
	(OBJ_obj2nid((a)->type) == NID_pkcs7_data)
#define CPK_PKCS7_set_detached(p,v)			\
	CPK_PKCS7_ctrl(p,CPK_PKCS7_OP_SET_DETACHED_SIGNATURE,v,NULL)
#define CPK_PKCS7_get_detached(p)			\
	CPK_PKCS7_ctrl(p,CPK_PKCS7_OP_GET_DETACHED_SIGNATURE,0,NULL)
#define CPK_PKCS7_is_detached(p7)			\
	(CPK_PKCS7_type_is_signed(p7) && CPK_PKCS7_get_detached(p7))


/* cpk_pkcs7.c */
	
/* CPK PKCS7 Functions */
long CPK_PKCS7_ctrl(CPK_PKCS7 *p7, int cmd, long larg, char *parg);
int CPK_PKCS7_set_type(CPK_PKCS7 *p7, int type);
int CPK_PKCS7_set_cipher(CPK_PKCS7 *p7, const EVP_CIPHER *cipher);
int CPK_PKCS7_set_content(CPK_PKCS7 *p7, CPK_PKCS7 *p7_data);
int CPK_PKCS7_content_new(CPK_PKCS7 *p7, int type);
int CPK_PKCS7_add_signer(CPK_PKCS7 *p7, const EVP_MD *sign_alg,
	const CPK_KEY_INFO *sign_key);
int CPK_PKCS7_add_recipient(CPK_PKCS7 *p7,
	const CPK_IDENTITY_INFO *id, const ECIES_PARAMS *params);


BIO *CPK_PKCS7_dataInit(CPK_PKCS7 *p7, BIO *bio);
BIO *CPK_PKCS7_dataDecode(CPK_PKCS7 *p7, BIO *in_bio, 
	const CPK_KEY_INFO *keyinfo);
int  CPK_PKCS7_dataUpdate(CPK_PKCS7 *p7, BIO *bio, 
	const unsigned char *data, int len);
int  CPK_PKCS7_dataFinal(CPK_PKCS7 *p7, BIO *bio);
STACK_OF(CPK_SIGNER_INFO) *CPK_PKCS7_get_signer_infos(CPK_PKCS7 *p7);
int CPK_PKCS7_dataVerify(CPK_PUBLIC_MATRIX *public_matrix, BIO *bio,
	CPK_PKCS7 *p7, CPK_SIGNER_INFO *si);


/* map algorithm */
int str2index(const EVP_MD *md, int col, int row,
	const char *str, int len, int index[]);

/* asn.1 fp and bio wrapper functions */
#define DECLARE_ASN1_IO_FUNCTIONS(TYPE)				\
	TYPE *d2i_##TYPE##_fp(FILE *fp, TYPE **pp);		\
	int i2d_##TYPE##_fp(FILE *fp, TYPE *p);			\
	TYPE *d2i_##TYPE##_bio(BIO *bp, TYPE **pp); 		\
	int i2d_##TYPE##_bio(BIO *bp, TYPE *p);			\
	TYPE *d2i_##TYPE##_file(const char *file, TYPE **pp);	\
	int i2d_##TYPE##_file(const char *file, TYPE *p);

DECLARE_ASN1_IO_FUNCTIONS(CPK_SECRET_MATRIX)
DECLARE_ASN1_IO_FUNCTIONS(CPK_PUBLIC_MATRIX)
DECLARE_ASN1_IO_FUNCTIONS(CPK_IDENTITY_INFO)
DECLARE_ASN1_IO_FUNCTIONS(CPK_KEY_INFO)
DECLARE_ASN1_IO_FUNCTIONS(CPK_SIGNER_INFO)
DECLARE_ASN1_IO_FUNCTIONS(CPK_RECIP_INFO)
DECLARE_ASN1_IO_FUNCTIONS(CPK_PKCS7)


/* ERR function (should in openssl/err.h) begin */
#define ERR_LIB_CPK		130
#define ERR_R_CPK_LIB		ERR_LIB_CPK
#define CPKerr(f,r) ERR_PUT_error(ERR_LIB_CPK,(f),(r),__FILE__,__LINE__)
/* end */


void ERR_load_CPK_strings(void);

/* Error codes for the ECIES functions. */

/* Function codes. */
#define CPK_F_CPK_SECRET_MATRIX_CREATE		100
#define CPK_F_CPK_PUBLIC_MATRIX_CREATE		101
#define CPK_F_CPK_IDENTITY_INFO_SET		102
#define CPK_F_CPK_IDENTITY_INFO_GET_KEY		103
#define CPK_F_CPK_KEY_INFO_CREATE		104
#define CPK_F_CPK_KEY_INFO_GET_KEY		129
#define CPK_F_CPK_PUBLIC_MATRIX_GET_KEY		105
#define CPK_F_CPK_SIGNER_INFO_SET		106
#define CPK_F_CPK_SIGNER_INFO_ADD_ATTR		107
#define CPK_F_CPK_SIGNER_INFO_ADD_SIGNED_ATTR	108
#define CPK_F_CPK_SIGNER_INFO_ADD_SIGNED_TIME	109
#define CPK_F_CPK_SIGNER_INFO_ADD_SIGNED_DIGEST	129
#define CPK_F_CPK_SIGNER_INFO_DO_SIGN		110
#define CPK_F_CPK_SIGNER_INFO_GET_ATTR		111
#define CPK_F_CPK_SIGNER_INFO_GET_SIGNED_ATTR	112
#define CPK_F_CPK_SIGNER_INFO_GET_SIGNED_TIME	113
#define CPK_F_CPK_SIGNER_INFO_DO_VERIFY		114
#define CPK_F_CPK_RECIP_INFO_SET		115
#define CPK_F_CPK_RECIP_INFO_DO_ENCRYPT		116
#define CPK_F_CPK_RECIP_INFO_DO_DECRYPT		117
#define CPK_F_CPK_PKCS7_SET_TYPE		118
#define CPK_F_CPK_PKCS7_SET_CONTENT		119
#define CPK_F_CPK_PKCS7_CONTENT_NEW		120
#define CPK_F_CPK_PKCS7_ADD_SIGNER		121
#define CPK_F_CPK_PKCS7_ADD_RECIPIENT		122
#define CPK_F_CPK_PKCS7_SET_CIPHER		123
#define CPK_F_CPK_PKCS7_DATAINIT		124
#define CPK_F_CPK_PKCS7_DATADECODE		130
#define CPK_F_CPK_PKCS7_DATAUPDATE		125
#define CPK_F_CPK_PKCS7_DATAFINAL		126
#define CPK_F_CPK_PKCS7_DATAVERIFY		130
#define CPK_F_CPK_PKCS7_FIND_DIGEST		127
#define CPK_F_BIO_ADD_DIGEST			128
#define CPK_F_BIO_ADD_CIPHER			129

/* Reason codes. */
#define CPK_R_BAD_ARGUMENT			100
#define CPK_R_UNKNOWN_DIGEST_TYPE		101
#define CPK_R_UNKNOWN_CIPHER_TYPE		102
#define CPK_R_UNKNOWN_MAP_TYPE			103
#define CPK_R_UNKNOWN_CURVE			104
#define CPK_R_STACK_ERROR			105
#define CPK_R_DERIVE_KEY_FAILED			106
#define CPK_R_ECIES_ENCRYPT_FAILED		107
#define CPK_R_ECIES_DECRYPT_FAILED		108
#define CPK_R_DER_DECODE_FAILED			109
#define CPK_R_UNSUPPORTED_PKCS7_CONTENT_TYPE	110
#define CPK_R_SET_SIGNER			111
#define CPK_R_SET_RECIP_INFO			112
#define CPK_R_UNABLE_TO_FIND_MESSAGE_DIGEST	113
#define CPK_R_BAD_DATA				114
#define CPK_R_MAP_FAILED			115
#define CPK_R_ADD_SIGNING_TIME			116
#define CPK_R_VERIFY_FAILED			117
#define	CPK_R_UNKNOWN_ECDH_TYPE			118
#define CPK_R_DIGEST_FAILED			119
#define CPK_R_WITHOUT_DECRYPT_KEY		120
#define CPK_R_UNKNOWN_PKCS7_TYPE		121


#ifdef  __cplusplus
}
#endif
#endif
