#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <security/cryptoki.h>
#include "cpkGlobal.h"
#include "cpkSession.h"
#include "cpkObject.h"
#include "cpkPlatform.h"
#include "cpkPkcs11.h"





//#pragma fini(cpktoken_fini)

static struct CK_FUNCTION_LIST functionList = {
	{ 2, 20 },	/* version */
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};

boolean_t cpktoken_initialized = B_FALSE;

static pid_t cpktoken_pid = 0;

/* This mutex protects cpk_session_list, all_sessions_closing */
pthread_mutex_t cpk_sessionlist_mutex;
cpk_session_t *cpk_session_list = NULL;

int all_sessions_closing = 0;


slot_t cpk_slot;
obj_to_be_freed_list_t obj_delay_freed;
ses_to_be_freed_list_t ses_delay_freed;

/* protects cpktoken_initialized and access to C_Initialize/C_Finalize */
pthread_mutex_t cpk_giant_mutex = PTHREAD_MUTEX_INITIALIZER;

static CK_RV finalize_common(boolean_t force, CK_VOID_PTR pReserved);
static void cpktoken_fini();

CK_RV
C_Initialize(CK_VOID_PTR pInitArgs)
{

	int initialize_pid;

	/*
	 * Get lock to insure only one thread enters this
	 * function at a time.
	 */
	(void) pthread_mutex_lock(&cpk_giant_mutex);

	initialize_pid = getpid();

	if (cpktoken_initialized) {
		if (initialize_pid == cpktoken_pid) {
			/*
			 * This process has called C_Initialize already
			 */
			(void) pthread_mutex_unlock(&cpk_giant_mutex);
			return (CKR_CRYPTOKI_ALREADY_INITIALIZED);
		} else {
			/*
			 * A fork has happened and the child is
			 * reinitializing.  Do a finalize_common to close
			 * out any state from the parent, and then
			 * continue on.
			 */
			(void) finalize_common(B_TRUE, NULL);
		}
	}

	if (pInitArgs != NULL) {
		/* do nothing */
	}

	/* Initialize the session list lock */
	if (pthread_mutex_init(&cpk_sessionlist_mutex, NULL) != 0) {
		(void) pthread_mutex_unlock(&cpk_giant_mutex);
		return (CKR_CANT_LOCK);
	}

	cpktoken_initialized = B_TRUE;
	cpktoken_pid = initialize_pid;

	/* Initialize the slot lock */
	if (pthread_mutex_init(&cpk_slot.slot_mutex, NULL) != 0) {
		//(void) cpk_destroy_token_session();
		(void) pthread_mutex_unlock(&cpk_giant_mutex);
		return (CKR_CANT_LOCK);
	}

	/* Initialize the keystore lock */
	//if (pthread_mutex_init(&cpk_slot.keystore_mutex, NULL) != 0) {
	//	(void) pthread_mutex_unlock(&cpk_giant_mutex);
	//	return (CKR_CANT_LOCK);
	//}

	(void) pthread_mutex_unlock(&cpk_giant_mutex);

	/* Initialize the object_to_be_freed list */
	(void) pthread_mutex_init(&obj_delay_freed.obj_to_be_free_mutex, NULL);
	obj_delay_freed.count = 0;
	obj_delay_freed.first = NULL;
	obj_delay_freed.last = NULL;

	(void) pthread_mutex_init(&ses_delay_freed.ses_to_be_free_mutex, NULL);
	ses_delay_freed.count = 0;
	ses_delay_freed.first = NULL;
	ses_delay_freed.last = NULL;

	(void) cpk_init_library();
	return (CKR_OK);

}


CK_RV
C_Finalize(CK_VOID_PTR pReserved)
{

	CK_RV rv;

	(void) pthread_mutex_lock(&cpk_giant_mutex);

	rv = finalize_common(B_FALSE, pReserved);

	(void) pthread_mutex_unlock(&cpk_giant_mutex);

	return (rv);

}

/*
 * finalize_common() does the work for C_Finalize.  cpk_giant_mutex
 * must be held before calling this function.
 */
static CK_RV
finalize_common(boolean_t force, CK_VOID_PTR pReserved) {

	CK_RV rv = CKR_OK;
#if 1
	struct object *delay_free_obj, *tmpo;
	struct session *delay_free_ses, *tmps;

	if (!cpktoken_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Check to see if pReseved is NULL */
	if (pReserved != NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	(void) pthread_mutex_lock(&cpk_sessionlist_mutex);
	/*
	 * Set all_sessions_closing flag so any access to any
	 * existing sessions will be rejected.
	 */
	all_sessions_closing = 1;
	(void) pthread_mutex_unlock(&cpk_sessionlist_mutex);

	/* Delete all the sessions and release the allocated resources */
	rv = cpk_delete_all_sessions(force);

	(void) pthread_mutex_lock(&cpk_sessionlist_mutex);
	/* Reset all_sessions_closing flag. */
	all_sessions_closing = 0;
	(void) pthread_mutex_unlock(&cpk_sessionlist_mutex);

	cpktoken_initialized = B_FALSE;
	cpktoken_pid = 0;

	/* Destroy the session list lock here */
	(void) pthread_mutex_destroy(&cpk_sessionlist_mutex);

	/*
	 * Destroy token object related stuffs
	 * 1. Clean up the token object list
	 * 2. Destroy slot mutex
	 * 3. Destroy mutex in token_session
	 */
	//(void) pthread_mutex_destroy(&cpk_slot.slot_mutex);
	//(void) pthread_mutex_destroy(&cpk_slot.keystore_mutex);

	/*
	 * free all entries in the delay_freed list
	 */
	delay_free_obj = obj_delay_freed.first;
	while (delay_free_obj != NULL) {
		tmpo = delay_free_obj->next;
		free(delay_free_obj);
		delay_free_obj = tmpo;
	}

	//cpk_slot.keystore_load_status = KEYSTORE_UNINITIALIZED;
	(void) pthread_mutex_destroy(&obj_delay_freed.obj_to_be_free_mutex);

	delay_free_ses = ses_delay_freed.first;
	while (delay_free_ses != NULL) {
		tmps = delay_free_ses->next;
		free(delay_free_ses);
		delay_free_ses = tmps;
	}
	(void) pthread_mutex_destroy(&ses_delay_freed.ses_to_be_free_mutex);
#endif
	return (rv);
}

/*
 * cpktoken_fini() function required to make sure complete cleanup
 * is done if cpktoken is ever unloaded without a C_Finalize() call.
 */
static void
cpktoken_fini()
{
	(void) pthread_mutex_lock(&cpk_giant_mutex);

	/* if we're not initilized, do not attempt to finalize */
	if (!cpktoken_initialized) {
		(void) pthread_mutex_unlock(&cpk_giant_mutex);
		return;
	}

	(void) finalize_common(B_TRUE, NULL_PTR);

	(void) pthread_mutex_unlock(&cpk_giant_mutex);
}

CK_RV
C_GetInfo(CK_INFO_PTR pInfo)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pInfo == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* Provide general information in the provided buffer */
	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	(void) strncpy((char *)pInfo->manufacturerID,
	    CPK_MANUFACTURER_ID, 32);
	pInfo->flags = 0;
	(void) strncpy((char *)pInfo->libraryDescription,
	    LIBRARY_DESCRIPTION, 32);
	pInfo->libraryVersion.major = LIBRARY_VERSION_MAJOR;
	pInfo->libraryVersion.minor = LIBRARY_VERSION_MINOR;

	return (CKR_OK);
}

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (ppFunctionList == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	*ppFunctionList = &functionList;

	return (CKR_OK);
}

/*
 * PKCS#11 states that C_GetFunctionStatus should always return
 * CKR_FUNCTION_NOT_PARALLEL
 */
/*ARGSUSED*/
CK_RV
C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	return (CKR_FUNCTION_NOT_PARALLEL);
}

/*
 * PKCS#11 states that C_CancelFunction should always return
 * CKR_FUNCTION_NOT_PARALLEL
 */
/*ARGSUSED*/
CK_RV
C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	return (CKR_FUNCTION_NOT_PARALLEL);
}


