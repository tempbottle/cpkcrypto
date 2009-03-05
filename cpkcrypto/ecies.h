/* Copyright (c) 2007  "Guan Zhi" <guanzhi1980@gmail.com> */

#ifndef HEADER_ECIES_H
#define HEADER_ECIES_H

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct ecies_ciphertext_st {
	X509_ALGOR		*algor;
	ASN1_OCTET_STRING	*encdata;
} ECIES_CIPHERTEXT;

typedef struct ecies_mactag_st {
	X509_ALGOR		*algor;
	ASN1_OCTET_STRING	*macdata;
} ECIES_MACTAG;

typedef struct ecies_ciphertext_value_st {
	ASN1_OCTET_STRING	*ephem_point;
	ASN1_OCTET_STRING	*ciphertext;
	ASN1_OCTET_STRING	*mactag;
} ECIES_CIPHERTEXT_VALUE;

DECLARE_ASN1_FUNCTIONS(ECIES_CIPHERTEXT)
DECLARE_ASN1_FUNCTIONS(ECIES_MACTAG)
DECLARE_ASN1_FUNCTIONS(ECIES_CIPHERTEXT_VALUE)


typedef struct ecies_params_st {
	int			is_cofactor_dh;
	const EVP_MD		*dh_kdf_md;
	const EVP_CIPHER	*enc_cipher;
	const EVP_MD		*enc_mac_md;
} ECIES_PARAMS;


typedef void *(*KDF_PTR)(const void *in, size_t inlen,
	void *out, size_t *outlen);

/** x963_kdf_from_md
 * X9.63 Key Derive Functions, used by ECDH
 */
KDF_PTR x963_kdf_from_md(const EVP_MD *md);

ECIES_CIPHERTEXT_VALUE *ECIES_do_encrypt(const ECIES_PARAMS *param,
	const unsigned char *in, size_t inlen, const EC_KEY *pub_key);
int ECIES_do_decrypt(const ECIES_CIPHERTEXT_VALUE *cv,
	ECIES_PARAMS *param, unsigned char *out, size_t *outlen, 
	const EC_KEY *sec_key);



/* ERR function (should in openssl/err.h) begin */
#define ERR_LIB_ECIES		129
#define ERR_R_ECIES_LIB		ERR_LIB_ECIES
#define ECIESerr(f,r) ERR_PUT_error(ERR_LIB_ECIES,(f),(r),__FILE__,__LINE__)
/* end */


void ERR_load_ECIES_strings(void);

/* Error codes for the ECIES functions. */

/* Function codes. */
#define ECIES_F_ECIES_DO_ENCRYPT	100
#define ECIES_F_ECIES_DO_DECRYPT	101

/* Reason codes. */
#define ECIES_R_BAD_DATA		100
#define ECIES_R_UNKNOWN_CIPHER_TYPE	101
#define ECIES_R_ENCRYPT_FAILED		102
#define ECIES_R_DECRYPT_FAILED		103
#define ECIES_R_UNKNOWN_MAC_TYPE	104
#define ECIES_R_GEN_MAC_FAILED		105
#define ECIES_R_VERIFY_MAC_FAILED	106
#define ECIES_R_ECDH_FAILED		107
#define ECIES_R_BUFFER_TOO_SMALL	108


#ifdef __cplusplus
}
#endif
#endif
