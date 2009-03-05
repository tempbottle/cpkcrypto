#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <security/cryptoki.h>
#include "pkcs11cpk.h"
#include "cpkSession.h"
#include "cpkObject.h"
#include "cpkOps.h"
#include "cpkPkcs11.h"



CK_RV
cpk_decrypt_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p)
{
	switch (pMechanism->mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECIES:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_MD5HMAC:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_SHA1HMAC:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CBC_PAD_SHA1HMAC:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CFB_SHA1HMAC:
		if (key_p->key_type != CKK_CPK) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}
		return (ri_decrypt_init(session_p, pMechanism, key_p));
	default:
		return (CKR_MECHANISM_INVALID);
	}
}

CK_RV
cpk_decrypt_common(cpk_session_t *session_p, CK_BYTE_PTR pEncrypted,
    CK_ULONG ulEncryptedLen, CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen, boolean_t Update)
{

	CK_MECHANISM_TYPE mechanism = session_p->decrypt.mech.mechanism;

	switch (mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECIES:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_MD5HMAC:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_SHA1HMAC:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CBC_PAD_SHA1HMAC:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CFB_SHA1HMAC:
		return (ri_decrypt(session_p, pEncrypted, ulEncryptedLen,
		    pData, pulDataLen));
	default:
		return (CKR_MECHANISM_INVALID);
	}
}

CK_RV
cpk_decrypt(cpk_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen)
{
	return (cpk_decrypt_common(session_p, pEncryptedData,
	    ulEncryptedDataLen, pData, pulDataLen, B_FALSE));
}
