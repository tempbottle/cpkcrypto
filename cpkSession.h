#ifndef _CPKSESSION_H
#define	_CPKSESSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <security/pkcs11t.h>
#include "cpkPlatform.h"


#define	CPKTOKEN_SESSION_MAGIC	0x10548869



typedef struct crypto_active_op {
	CK_MECHANISM	mech;
	void		*context;
	uint32_t	flags;
} crypto_active_op_t;


/*
 * Definition for flags in crypto_active_op_t
 */
#define	CRYPTO_OPERATION_ACTIVE		1 /* Cryptoki operation is active */
#define	CRYPTO_OPERATION_UPDATE		2 /* Cryptoki multi-part op active */


typedef struct session {
	ulong_t		magic_marker;	/* magic # be validated for integrity */
	pthread_mutex_t	session_mutex;	/* session's mutex lock */
	pthread_cond_t	ses_free_cond;	/* cond variable for signal and wait */
	uint32_t	ses_refcnt;	/* session reference count */
	uint32_t	ses_close_sync;	/* session closing flags */
	CK_STATE	state;		/* session state */

	/* Place holder for parameters passed in the C_OpenSession */
	CK_FLAGS	flags;
	CK_NOTIFY	Notify;
	CK_VOID_PTR	pApplication;

	/* Pointers to form the global session list */
	struct session	*next;		/* points to next session on the list */
	struct session	*prev;		/* points to prev session on the list */

	struct object	*object_list;	/* points to list of objects */

	crypto_active_op_t	digest;	/* context of active digest operation */
	crypto_active_op_t	encrypt; /* context of active encrypt op */
	crypto_active_op_t	decrypt; /* context of active decrypt op */
	crypto_active_op_t	sign;	/* context of active sign op */
	crypto_active_op_t	verify;	/* context of active verify op */
} cpk_session_t;

/*
 * slot_t is a global structure to be used only by the
 * token objects to hold the token object related
 * in-core information.
 */
typedef struct slot {

	pthread_mutex_t	slot_mutex;

} slot_t;

/*
 * The following structure is used to link the to-be-freed sessions
 * into a linked list. The sessions on this linked list have
 * not yet been freed via free() after C_CloseSession() call; instead
 * they are added to this list. The actual free will take place when
 * the number of sessions queued reaches MAX_SES_TO_BE_FREED, at which
 * time the first session in the list will be freed.
 */
#define	MAX_SES_TO_BE_FREED		300

typedef struct ses_to_be_freed_list {
	struct session	*first;	/* points to the first session in the list */
	struct session	*last;	/* points to the last session in the list */
	uint32_t	count;	/* current total sessions in the list */
	pthread_mutex_t	ses_to_be_free_mutex;
} ses_to_be_freed_list_t;

/*
 * Flag definitions for ses_close_sync
 */
#define	SESSION_IS_CLOSING	1	/* Session is in a closing state */
#define	SESSION_REFCNT_WAITING	2	/* Waiting for session reference */
					/* count to become zero */

#define	SES_REFRELE(s, lock_held) { \
	if (!lock_held) \
		(void) pthread_mutex_lock(&s->session_mutex);   \
	if ((--((s)->ses_refcnt) == 0) &&    \
	    (s->ses_close_sync & SESSION_REFCNT_WAITING)) {     \
		(void) pthread_mutex_unlock(&s->session_mutex);   \
		(void) pthread_cond_signal(&s->ses_free_cond); \
	} else {        \
		(void) pthread_mutex_unlock(&s->session_mutex);   \
	}       \
}


extern pthread_mutex_t cpk_sessionlist_mutex;
extern cpk_session_t *cpk_session_list;
extern int all_sessions_closing;
extern CK_ULONG cpk_session_cnt;	/* the number of opened sessions */
extern CK_ULONG cpk_session_rw_cnt;	/* the number of opened R/W sessions */


/*
 * Function Prototypes.
 */
CK_RV handle2session(CK_SESSION_HANDLE hSession, cpk_session_t **session_p);
CK_RV cpk_delete_all_sessions(boolean_t force);
void cpk_delete_all_objects_in_session(cpk_session_t *sp);
CK_RV cpk_add_session(CK_FLAGS flags, CK_VOID_PTR pApplication,
    CK_NOTIFY notify, CK_ULONG *phSession);
CK_RV cpk_delete_session(cpk_session_t *sp,
    boolean_t force, boolean_t lock_held);



#ifdef	__cplusplus
}
#endif
#endif
