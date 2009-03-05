#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <security/cryptoki.h>
#include "cpkGlobal.h"
#include "cpkSession.h"
#include "cpkObject.h"
#include "cpkOps.h"
#include "cpkPkcs11.h"



CK_ULONG cpk_session_cnt = 0;		/* the number of opened sessions */
CK_ULONG cpk_session_rw_cnt = 0;	/* the number of opened R/W sessions */

/*
 * Delete all the sessions. First, obtain the global session
 * list lock. Then start to delete one session at a time.
 * Release the global session list lock before returning to
 * caller.
 */
CK_RV
cpk_delete_all_sessions(boolean_t force)
{

	CK_RV rv = CKR_OK;
	CK_RV rv1;
	cpk_session_t *session_p;
	cpk_session_t *session_p1;

	/* Acquire the global session list lock */
	(void) pthread_mutex_lock(&cpk_sessionlist_mutex);

	session_p = cpk_session_list;

	/* Delete all the sessions in the session list */
	while (session_p) {
		session_p1 = session_p->next;

		/*
		 * Delete a session by calling cpk_delete_session()
		 * with a session pointer and a boolean arguments.
		 * Boolean value TRUE is used to indicate that the
		 * caller holds the lock on the global session list.
		 *
		 */
		rv1 = cpk_delete_session(session_p, force, B_TRUE);

		/* Record the very first error code */
		if (rv == CKR_OK) {
			rv = rv1;
		}

		session_p = session_p1;
	}

	/* No session left */
	cpk_session_list = NULL;

	/* Release the global session list lock */
	(void) pthread_mutex_unlock(&cpk_sessionlist_mutex);

	return (rv);

}


/*
 * Create a new session struct, and add it to the session linked list.
 *
 * This function will acquire the global session list lock, and release
 * it after adding the session to the session linked list.
 */
CK_RV
cpk_add_session(CK_FLAGS flags, CK_VOID_PTR pApplication,
	CK_NOTIFY notify, CK_ULONG *sessionhandle_p)
{

	cpk_session_t *new_sp = NULL;

	/* Allocate a new session struct */
	new_sp = calloc(1, sizeof (cpk_session_t));
	if (new_sp == NULL) {
		return (CKR_HOST_MEMORY);
	}

	new_sp->magic_marker = CPKTOKEN_SESSION_MAGIC;
	new_sp->pApplication = pApplication;
	new_sp->Notify = notify;
	new_sp->flags = flags;
	new_sp->state = CKS_RO_PUBLIC_SESSION;
	new_sp->object_list = NULL;
	new_sp->ses_refcnt = 0;
	new_sp->ses_close_sync = 0;

	(void) pthread_mutex_unlock(&cpk_giant_mutex);
	if (flags & CKF_RW_SESSION) {
		new_sp->state = CKS_RW_PUBLIC_SESSION;
	} else {
		new_sp->state = CKS_RO_PUBLIC_SESSION;
	}

	/* Initialize the lock for the newly created session */
	if (pthread_mutex_init(&new_sp->session_mutex, NULL) != 0) {
		free(new_sp);
		return (CKR_CANT_LOCK);
	}

	(void) pthread_cond_init(&new_sp->ses_free_cond, NULL);

	/* Acquire the global session list lock */
	(void) pthread_mutex_lock(&cpk_sessionlist_mutex);

	/* Insert the new session in front of session list */
	if (cpk_session_list == NULL) {
		cpk_session_list = new_sp;
		new_sp->next = NULL;
		new_sp->prev = NULL;
	} else {
		cpk_session_list->prev = new_sp;
		new_sp->next = cpk_session_list;
		new_sp->prev = NULL;
		cpk_session_list = new_sp;
	}

	/* Type casting the address of a session struct to a session handle */
	*sessionhandle_p =  (CK_ULONG)new_sp;
	++cpk_session_cnt;
	if (flags & CKF_RW_SESSION)
		++cpk_session_rw_cnt;

	/* Release the global session list lock */
	(void) pthread_mutex_unlock(&cpk_sessionlist_mutex);

	return (CKR_OK);

}

/*
 * This function adds the to-be-freed session to a linked list.
 * When the number of sessions queued in the linked list reaches the
 * maximum threshold MAX_SES_TO_BE_FREED, it will free the first
 * session (FIFO) in the list.
 */
void
session_delay_free(cpk_session_t *sp)
{
	cpk_session_t *tmp;

	(void) pthread_mutex_lock(&ses_delay_freed.ses_to_be_free_mutex);

	/* Add the newly deleted session at the end of the list */
	sp->next = NULL;
	if (ses_delay_freed.first == NULL) {
		ses_delay_freed.last = sp;
		ses_delay_freed.first = sp;
	} else {
		ses_delay_freed.last->next = sp;
		ses_delay_freed.last = sp;
	}

	if (++ses_delay_freed.count >= MAX_SES_TO_BE_FREED) {
		/*
		 * Free the first session in the list only if
		 * the total count reaches maximum threshold.
		 */
		ses_delay_freed.count--;
		tmp = ses_delay_freed.first->next;
		free(ses_delay_freed.first);
		ses_delay_freed.first = tmp;
	}
	(void) pthread_mutex_unlock(&ses_delay_freed.ses_to_be_free_mutex);
}

/*
 * Delete a session:
 * - Remove the session from the session linked list.
 *   Holding the lock on the global session list is needed to do this.
 * - Release all the objects created by the session.
 *
 * The boolean argument lock_held is used to indicate that whether
 * the caller of this function holds the lock on the global session
 * list or not.
 * - When called by cpk_delete_all_sessions(), which is called by
 *   C_Finalize() or C_CloseAllSessions() -- the lock_held = TRUE.
 * - When called by C_CloseSession() -- the lock_held = FALSE.
 *
 * When the caller does not hold the lock on the global session
 * list, this function will acquire that lock in order to proceed,
 * and also release that lock before returning to caller.
 */
CK_RV
cpk_delete_session(cpk_session_t *session_p,
    boolean_t force, boolean_t lock_held)
{

	/*
	 * Check to see if the caller holds the lock on the global
	 * session list. If not, we need to acquire that lock in
	 * order to proceed.
	 */
	if (!lock_held) {
		/* Acquire the global session list lock */
		(void) pthread_mutex_lock(&cpk_sessionlist_mutex);
	}

	/*
	 * Remove the session from the session linked list first.
	 */
	if (cpk_session_list == session_p) {
		/* Session is the first one in the list */
		if (session_p->next) {
			cpk_session_list = session_p->next;
			session_p->next->prev = NULL;
		} else {
			/* Session is the only one in the list */
			cpk_session_list = NULL;
		}
	} else {
		/* Session is not the first one in the list */
		if (session_p->next) {
			/* Session is in the middle of the list */
			session_p->prev->next = session_p->next;
			session_p->next->prev = session_p->prev;
		} else {
			/* Session is the last one in the list */
			session_p->prev->next = NULL;
		}
	}

	--cpk_session_cnt;
	if (session_p->flags & CKF_RW_SESSION)
		--cpk_session_rw_cnt;

	if (!lock_held) {
		/*
		 * If the global session list lock is obtained by
		 * this function, then release that lock after
		 * removing the session from session linked list.
		 * We want the releasing of the objects of the
		 * session, and freeing of the session itself to
		 * be done without holding the global session list
		 * lock.
		 */
		(void) pthread_mutex_unlock(&cpk_sessionlist_mutex);
	}


	/* Acquire the individual session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	/*
	 * Make sure another thread hasn't freed the session.
	 */
	if (session_p->magic_marker != CPKTOKEN_SESSION_MAGIC) {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		return (CKR_OK);
	}

	/*
	 * The deletion of a session must be blocked when the session
	 * reference count is not zero. This means if any session related
	 * operation starts prior to the session close operation gets in,
	 * the session closing thread must wait for the non-closing
	 * operation to be completed before it can proceed the close
	 * operation.
	 *
	 * Unless we are being forced to shut everything down, this only
	 * happens if the libraries _fini() is running not of someone
	 * explicitly called C_Finalize().
	 */
	if (force)
		session_p->ses_refcnt = 0;

	while (session_p->ses_refcnt != 0) {
		/*
		 * We set the SESSION_REFCNT_WAITING flag before we put
		 * this closing thread in a wait state, so other non-closing
		 * operation thread will signal to wake it up only when
		 * the session reference count becomes zero and this flag
		 * is set.
		 */
		session_p->ses_close_sync |= SESSION_REFCNT_WAITING;
		(void) pthread_cond_wait(&session_p->ses_free_cond,
			&session_p->session_mutex);
	}

	session_p->ses_close_sync &= ~SESSION_REFCNT_WAITING;

	/* Mark session as no longer valid. */
	session_p->magic_marker = 0;

	(void) pthread_cond_destroy(&session_p->ses_free_cond);

	/*
	 * Remove all the objects created in this session.
	 */
	cpk_delete_all_objects_in_session(session_p);

	/* In case application did not call Final */
	if (session_p->digest.context != NULL)
		free(session_p->digest.context);

	if (session_p->encrypt.context != NULL)
		/*
		 * 1st B_TRUE: encrypt
		 * 2nd B_TRUE: caller is holding session_mutex.
		 */
		//cpk_crypt_cleanup(session_p, B_TRUE, B_TRUE);

	if (session_p->decrypt.context != NULL)
		/*
		 * 1st B_FALSE: decrypt
		 * 2nd B_TRUE: caller is holding session_mutex.
		 */
		//cpk_crypt_cleanup(session_p, B_FALSE, B_TRUE);

	if (session_p->sign.context != NULL)
		free(session_p->sign.context);

	if (session_p->verify.context != NULL)
		free(session_p->verify.context);


	/* Reset SESSION_IS_CLOSIN flag. */
	session_p->ses_close_sync &= ~SESSION_IS_CLOSING;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	/* Destroy the individual session lock */
	(void) pthread_mutex_destroy(&session_p->session_mutex);

	/* Delay freeing the session */
	session_delay_free(session_p);

	return (CKR_OK);
}


CK_RV
handle2session(CK_SESSION_HANDLE hSession, cpk_session_t **session_p)
{

	cpk_session_t *sp = (cpk_session_t *)(hSession);

	(void) pthread_mutex_lock(&cpk_sessionlist_mutex);
	if (all_sessions_closing) {
		(void) pthread_mutex_unlock(&cpk_sessionlist_mutex);
		return (CKR_SESSION_CLOSED);
	}
	/*
	 * We need to free the global session list lock to prevent deadlock
	 * between C_CloseSession and C_DestroyObject. S1WS/NSS does
	 * explicit deletion (C_DestroyObject) after implicit deletion by
	 * C_CloseSession.
	 */
	(void) pthread_mutex_unlock(&cpk_sessionlist_mutex);

	if ((sp == NULL) ||
	    (sp->magic_marker != CPKTOKEN_SESSION_MAGIC)) {
		return (CKR_SESSION_HANDLE_INVALID);
	}
	(void) pthread_mutex_lock(&sp->session_mutex);

	if (sp->ses_close_sync & SESSION_IS_CLOSING) {
		(void) pthread_mutex_unlock(&sp->session_mutex);
		return (CKR_SESSION_CLOSED);
	}

	/* Increment session ref count. */
	sp->ses_refcnt++;

	(void) pthread_mutex_unlock(&sp->session_mutex);

	*session_p = sp;

	return (CKR_OK);
}


