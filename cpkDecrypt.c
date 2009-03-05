#include <pthread.h>
#include <security/cryptoki.h>
#include "cpkGlobal.h"
#include "cpkSession.h"
#include "cpkObject.h"
#include "cpkOps.h"


CK_RV
C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{

	CK_RV		rv;

	cpk_session_t	*session_p;
	cpk_object_t	*key_p;
	boolean_t	lock_held = B_FALSE;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pMechanism == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hKey, key_p, rv);
	if (rv != CKR_OK)
		goto clean_exit;

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/* Check to see if decrypt operation is already active. */
	if (session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE) {
		/* free the memory to avoid memory leak */
		cpk_crypt_cleanup(session_p, B_FALSE, lock_held);
	}

	/*
	 * This active flag will remain ON until application calls either
	 * C_Decrypt or C_DecryptFinal to actually obtain the final piece
	 * of plaintext.
	 */
	session_p->decrypt.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = cpk_decrypt_init(session_p, pMechanism, key_p);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->decrypt.flags &= ~CRYPTO_OPERATION_ACTIVE;
		lock_held = B_TRUE;
	}

	OBJ_REFRELE(key_p);
clean_exit:
	SES_REFRELE(session_p, lock_held);

	return (rv);
}

CK_RV
C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{

	CK_RV		rv;
	cpk_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obatin the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * Only check if input buffer is null.  How to handle zero input
	 * length depents on the mechanism in use.  For secret key mechanisms,
	 * unpadded ones yield zero length output, but padded ones always
	 * result in smaller than original, possibly zero, length output.
	 */
	if (pEncryptedData == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/*
	 * No need to check pData because application might
	 * just want to know the length of decrypted data.
	 */
	if (pulDataLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/* Application must call C_DecryptInit before calling C_Decrypt. */
	if (!(session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/*
	 * C_Decrypt must be called without intervening C_DecryptUpdate
	 * calls.
	 */
	if (session_p->decrypt.flags & CRYPTO_OPERATION_UPDATE) {
		/*
		 * C_Decrypt can not be used to terminate a multi-part
		 * operation, so we'll leave the active decrypt operation
		 * flag on and let the application continue with the
		 * decrypt update operation.
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = cpk_decrypt(session_p, pEncryptedData, ulEncryptedDataLen,
	    pData, pulDataLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pData == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active decrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the plaintext.
		 */
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/* Clear context, free key, and release session counter */
	cpk_crypt_cleanup(session_p, B_FALSE, B_FALSE);
	return (rv);
}


CK_RV
C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
    CK_ULONG_PTR pulLastPartLen)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}
