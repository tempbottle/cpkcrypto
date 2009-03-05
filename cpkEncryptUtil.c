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
cpk_encrypt_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p)
{

	switch (pMechanism->mechanism) {
	case CKM_CPK:
		return (CKR_MECHANISM_INVALID);
	case CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_SHA1HMAC:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CBC_PAD_SHA1HMAC:
		if ((key_p->class != CKO_PUBLIC_KEY) ||
		    (key_p->key_type != CKK_CPK)) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}
		return ri_encrypt_init(session_p, pMechanism, key_p);
	default:
		return (CKR_MECHANISM_INVALID);
	}

}

CK_RV
cpk_encrypt(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_MECHANISM_TYPE mechanism = session_p->encrypt.mech.mechanism;

	switch (mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECIES:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_MD5HMAC:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_SHA1HMAC:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CBC_PAD_SHA1HMAC:
	case CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CFB_SHA1HMAC:
		return (ri_encrypt(session_p, pData, ulDataLen, pEncryptedData,
			pulEncryptedDataLen));

	default:
		return (CKR_MECHANISM_INVALID);
	}
}


void
cpk_crypt_cleanup(cpk_session_t *session_p, boolean_t encrypt,
	boolean_t lock_held)
{

	crypto_active_op_t *active_op;
	boolean_t lock_true = B_TRUE;

	if (!lock_held)
		(void) pthread_mutex_lock(&session_p->session_mutex);

	active_op = (encrypt) ? &(session_p->encrypt) : &(session_p->decrypt);

	switch (active_op->mech.mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECIES:
		if (active_op != NULL) {
			CPK_RECIP_INFO_free((CPK_RECIP_INFO *)active_op->context);
			active_op->context = NULL;
		}

		break;
	}

	if (active_op->context != NULL) {
		free(active_op->context);
		active_op->context = NULL;
	}

	active_op->flags = 0;

	if (!lock_held)
		SES_REFRELE(session_p, lock_true);
}
