#include <pthread.h>
#include <security/cryptoki.h>
#include "cpkGlobal.h"
#include "cpkSession.h"
#include "cpkObject.h"



CK_RV
C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{

	CK_RV rv = CKR_OK;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (!(flags & CKF_SERIAL_SESSION))
		return (CKR_SESSION_PARALLEL_NOT_SUPPORTED);

	if (slotID != CPKTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	if (phSession == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = cpk_add_session(flags, pApplication, Notify, phSession);

	return (rv);

}

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{

	CK_RV rv;
	cpk_session_t *session_p;
	boolean_t lock_held = B_TRUE;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&session_p->session_mutex);

	if (session_p->ses_close_sync & SESSION_IS_CLOSING) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_SESSION_CLOSED);
	}
	session_p->ses_close_sync |= SESSION_IS_CLOSING;


	SES_REFRELE(session_p, lock_held);

	rv = cpk_delete_session(session_p, B_FALSE, B_FALSE);


	return (rv);
}


CK_RV
C_CloseAllSessions(CK_SLOT_ID slotID)
{

	CK_RV rv = CKR_OK;
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != CPKTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	/* Acquire the global session list lock */
	(void) pthread_mutex_lock(&cpk_sessionlist_mutex);
	/*
	 * Set all_sessions_closing flag so any access to any
	 * existing sessions will be rejected.
	 */
	all_sessions_closing = 1;
	(void) pthread_mutex_unlock(&cpk_sessionlist_mutex);

	/* Delete all the sessions and release the allocated resources */
	rv = cpk_delete_all_sessions(B_FALSE);


	(void) pthread_mutex_lock(&cpk_sessionlist_mutex);
	all_sessions_closing = 0;
	(void) pthread_mutex_unlock(&cpk_sessionlist_mutex);

	return (rv);
}

CK_RV
C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{

	cpk_session_t *session_p;
	CK_RV rv;
	boolean_t lock_held = B_TRUE;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pInfo == NULL) {
		lock_held = B_FALSE;
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* Provide information for the specified session */
	pInfo->slotID = CPKTOKEN_SLOTID;
	pInfo->state = session_p->state;
	pInfo->flags = session_p->flags;
	pInfo->ulDeviceError = 0;

clean_exit:
	SES_REFRELE(session_p, lock_held);

	return (CKR_OK);
}


CK_RV
C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG_PTR pulOperationStateLen)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);

}


CK_RV
C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
    CK_OBJECT_HANDLE hAuthenticationKey)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen)
{

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);

}

CK_RV
C_Logout(CK_SESSION_HANDLE hSession)
{

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);

}
