#include <pthread.h>
#include <security/cryptoki.h>
#include "cpkGlobal.h"
#include "cpkSession.h"
#include "cpkObject.h"
#include "cpkOps.h"


CK_RV
C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{

	CK_RV		rv;
	cpk_session_t	*session_p;
	cpk_object_t	*key_p;
	boolean_t	lock_held = B_FALSE;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pMechanism == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	HANDLE2OBJECT(hKey, key_p, rv);
	if (rv != CKR_OK)
		goto clean_exit;


	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	if (session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE) {
		cpk_crypt_cleanup(session_p, B_TRUE, lock_held);
	}

	session_p->encrypt.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = cpk_encrypt_init(session_p, pMechanism, key_p);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->encrypt.flags &= ~CRYPTO_OPERATION_ACTIVE;
		lock_held = B_TRUE;
	}

	OBJ_REFRELE(key_p);
clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}


CK_RV
C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{

	CK_RV		rv;
	cpk_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pData == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	if (pulEncryptedDataLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	if (!(session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	if (session_p->encrypt.flags & CRYPTO_OPERATION_UPDATE) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = cpk_encrypt(session_p, pData, ulDataLen, pEncryptedData,
	    pulEncryptedDataLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pEncryptedData == NULL && rv == CKR_OK)) {
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	cpk_crypt_cleanup(session_p, B_TRUE, B_FALSE);
	return (rv);
}


CK_RV
C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}


CK_RV
C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
    CK_ULONG_PTR pulLastEncryptedPartLen)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}
