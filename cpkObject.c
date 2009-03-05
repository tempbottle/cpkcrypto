#include <pthread.h>
#include <stdlib.h>
#include <security/cryptoki.h>
#include "cpkGlobal.h"
#include "cpkObject.h"
#include "cpkSession.h"



CK_RV
C_CreateObject(CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV rv;
	cpk_session_t *session_p;
	boolean_t lock_held = B_FALSE;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pTemplate == NULL) || (ulCount == 0) ||
	    (phObject == NULL)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	rv = cpk_add_object(pTemplate, ulCount, phObject, session_p);

clean_exit:

	SES_REFRELE(session_p, lock_held);
	return (rv);
}


CK_RV
C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phNewObject)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{

	CK_RV rv;
	cpk_object_t *object_p;
	cpk_session_t *session_p = (cpk_session_t *)(hSession);
	boolean_t lock_held = B_FALSE;
	CK_SESSION_HANDLE creating_session;


	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if ((session_p == NULL) ||
	    (session_p->magic_marker != CPKTOKEN_SESSION_MAGIC)) {
		return (CKR_SESSION_HANDLE_INVALID);
	}

	HANDLE2OBJECT_DESTROY(hObject, object_p, rv);
	if (rv != CKR_OK) {
		return (rv);
	}

	creating_session = object_p->session_handle;

	if (creating_session == (CK_SESSION_HANDLE)NULL) {
		rv = handle2session(hSession, &session_p);
		if (rv != CKR_OK) {
			return (rv);
		}

		(void) pthread_mutex_lock(&object_p->object_mutex);
		if (object_p->obj_delete_sync & OBJECT_IS_DELETING) {
			(void) pthread_mutex_unlock(&object_p->object_mutex);
			SES_REFRELE(session_p, lock_held);
			return (CKR_OBJECT_HANDLE_INVALID);
		}
		object_p->obj_delete_sync |= OBJECT_IS_DELETING;
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		SES_REFRELE(session_p, lock_held);


		return (CKR_OK);
	}

	rv = handle2session(creating_session, &session_p);
	if (rv != CKR_OK) {
		return (rv);
	}

	(void) pthread_mutex_lock(&object_p->object_mutex);
	if (object_p->obj_delete_sync & OBJECT_IS_DELETING) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		SES_REFRELE(session_p, lock_held);
		return (CKR_OBJECT_HANDLE_INVALID);
	}
	object_p->obj_delete_sync |= OBJECT_IS_DELETING;
	(void) pthread_mutex_unlock(&object_p->object_mutex);

	// **********************************************************
	//cpk_delete_object(session_p, object_p, B_FALSE);

	SES_REFRELE(session_p, lock_held);

	return (rv);
}


CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{

	CK_RV rv = CKR_OK, rv1 = CKR_OK;
	cpk_object_t *object_p;
	cpk_session_t *session_p;
	boolean_t lock_held = B_FALSE;
	ulong_t i;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pTemplate == NULL) || (ulCount == 0)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	HANDLE2OBJECT(hObject, object_p, rv);
	if (rv != CKR_OK) {
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

	(void) pthread_mutex_lock(&object_p->object_mutex);

	for (i = 0; i < ulCount; i++) {
		rv = cpk_get_attribute(object_p, &pTemplate[i]);
		if (rv != CKR_OK)
			/* At least we catch some type of error. */
			rv1 = rv;
	}

	/* Release the object lock */
	(void) pthread_mutex_unlock(&object_p->object_mutex);

	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	OBJ_REFRELE(object_p);
	SES_REFRELE(session_p, lock_held);

	rv = rv1;
	return (rv);
}


CK_RV
C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ULONG_PTR pulSize)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE sh, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
C_FindObjects(CK_SESSION_HANDLE sh,
    CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE sh)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}
