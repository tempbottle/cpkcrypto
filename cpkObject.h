#ifndef	_CPKOBJECT_H
#define	_CPKOBJECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <security/pkcs11t.h>
#include "pkcs11cpk.h"
#include "cpkSession.h"
#include "cpkcrypto/cpk.h"


#define	CPKTOKEN_OBJECT_MAGIC	0xECF0B007

typedef struct object {

	CK_OBJECT_CLASS 	class;
	CK_KEY_TYPE		key_type;
	CK_DATA_TYPE		data_type;
	ulong_t			magic_marker;
	CK_MECHANISM_TYPE	mechanism;

	pthread_mutex_t	object_mutex;
	struct object *next;
	struct object *prev;

	union {
		CPK_PUBLIC_MATRIX *public_matrix;
		CPK_SECRET_MATRIX *secret_matrix;
		CPK_IDENTITY_INFO *identity_info;
		CPK_KEY_INFO      *key_info;

		CPK_SIGNER_INFO	  *signer_info;
		CPK_RECIP_INFO    *recip_info;
		CPK_PKCS7         *pkcs7;
	} object_u;

	CK_SESSION_HANDLE	session_handle;
	uint32_t		obj_refcnt;
	pthread_cond_t		obj_free_cond;
	uint32_t		obj_delete_sync;

} cpk_object_t;


#define	MAX_OBJ_TO_BE_FREED		300

typedef struct obj_to_be_freed_list {
	struct object	*first;	/* points to the first obj in the list */
	struct object	*last;	/* points to the last obj in the list */
	uint32_t	count;	/* current total objs in the list */
	pthread_mutex_t	obj_to_be_free_mutex;
} obj_to_be_freed_list_t;


/*
 * Flag definitions for obj_delete_sync
 */
#define	OBJECT_IS_DELETING	1	/* Object is in a deleting state */
#define	OBJECT_REFCNT_WAITING	2	/* Waiting for object reference */
					/* count to become zero */


#define	HANDLE2OBJECT_COMMON(hObject, object_p, rv, REFCNT_CODE) { \
	object_p = (cpk_object_t *)(hObject); \
	if ((object_p == NULL) || \
		(object_p->magic_marker != CPKTOKEN_OBJECT_MAGIC)) {\
			rv = CKR_OBJECT_HANDLE_INVALID; \
	} else { \
		(void) pthread_mutex_lock(&object_p->object_mutex); \
		if (!(object_p->obj_delete_sync & OBJECT_IS_DELETING)) { \
			REFCNT_CODE; \
			rv = CKR_OK; \
		} else { \
			rv = CKR_OBJECT_HANDLE_INVALID; \
		} \
		(void) pthread_mutex_unlock(&object_p->object_mutex); \
	} \
}

#define	HANDLE2OBJECT(hObject, object_p, rv) \
	HANDLE2OBJECT_COMMON(hObject, object_p, rv, object_p->obj_refcnt++)

#define	HANDLE2OBJECT_DESTROY(hObject, object_p, rv) \
	HANDLE2OBJECT_COMMON(hObject, object_p, rv, /* no refcnt increment */)


#define	OBJ_REFRELE(object_p) { \
	(void) pthread_mutex_lock(&object_p->object_mutex); \
	if ((--object_p->obj_refcnt) == 0 && \
	    (object_p->obj_delete_sync & OBJECT_REFCNT_WAITING)) { \
		(void) pthread_cond_signal(&object_p->obj_free_cond); \
	} \
	(void) pthread_mutex_unlock(&object_p->object_mutex); \
}

/*
 * Function Prototypes.
 */
CK_RV cpk_build_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object);

CK_RV cpk_add_object(CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulCount,
	CK_ULONG *objecthandle_p, cpk_session_t *sp);

void cpk_add_object_to_session(cpk_object_t *objp, cpk_session_t *sp);

void cpk_cleanup_object(cpk_object_t *objp);

CK_RV cpk_copy_object(cpk_object_t *old_object, cpk_object_t **new_object,
    CK_ULONG object_func, cpk_session_t *sp);

CK_RV cpk_remove_object_from_session(cpk_object_t *objp, cpk_session_t *sp);

void object_delay_free(cpk_object_t *objp);
void cpk_delete_object(cpk_session_t *sp, cpk_object_t *objp, boolean_t lock_held);
void cpk_delete_all_objects_in_session(cpk_session_t *sp);

/* cpkAttributeUtil.c */
CK_RV get_string_attr_from_object(CK_BYTE_PTR pValue, CK_ULONG ulValueLen,
    CK_ATTRIBUTE_PTR template);
CK_RV get_ulong_attr_from_object(CK_ULONG value, CK_ATTRIBUTE_PTR template);
CK_RV get_bool_attr(CK_BBOOL value, CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_public_key_attribute(cpk_object_t *object_p,
    CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_private_key_attribute(cpk_object_t *object_p,
    CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_data_attribute(cpk_object_t *object_p,
    CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_signer_info_attribute(cpk_object_t *object_p,
    CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_recip_info_attribute(cpk_object_t *object_p,
    CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_pkcs7_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_public_matrix_attribute(cpk_object_t *object_p,
    CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_secret_matrix_attribute(cpk_object_t *object_p,
    CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_identitiy_info_attribute(cpk_object_t *object_p,
    CK_ATTRIBUTE_PTR template);
CK_RV cpk_get_key_info_attribute(cpk_object_t *object_p,
    CK_ATTRIBUTE_PTR template);



#ifdef	__cplusplus
}
#endif
#endif
