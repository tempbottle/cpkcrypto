#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include "pkcs11cpk.h"
#include "cpkGlobal.h"
#include "cpkObject.h"
#include "cpkSession.h"
#include "cpkPkcs11.h"

CK_RV
cpk_build_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object)
{
	CK_OBJECT_CLASS obj_class = (CK_OBJECT_CLASS)~0UL;
	CK_KEY_TYPE key_type = (CK_KEY_TYPE)~0UL;
	CK_DATA_TYPE data_type = (CK_DATA_TYPE)~0UL;
	unsigned char *der = NULL, *id = NULL;
	unsigned int derlen = 0, idlen = 0;
	CK_ULONG i;


	for (i = 0; i < ulAttrNum; i++) {
		switch (template[i].type) {
		case CKA_CLASS:
			obj_class = *((CK_OBJECT_CLASS*)template[i].pValue);
			break;
		case CKA_KEY_TYPE:
			key_type = *((CK_KEY_TYPE *)template[i].pValue);
			break;
		case CKA_DATA_TYPE:
			data_type = *((CK_DATA_TYPE *)template[i].pValue);
			break;
		case CKA_CPK_DER:
		case CKA_CPK_ID:
			break;
		default:
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}
	}

	switch (obj_class) {
	case CKO_PUBLIC_KEY:
		switch (key_type) {
		case CKK_CPK:
			return (cpk_build_public_key_object(template,
				ulAttrNum, new_object));
		case CKK_CPK_MATRIX:
			return (cpk_build_public_matrix_object(template,
				ulAttrNum, new_object));
		default:
			return (CKR_KEY_TYPE_INCONSISTENT);
		}
		break;
	case CKO_PRIVATE_KEY:
		switch (key_type) {
		case CKK_CPK:
			return (cpk_build_private_key_object(template,
				ulAttrNum, new_object));
		default:
			return (CKR_KEY_TYPE_INCONSISTENT);
		}
		break;
	case CKO_DATA:
		switch (data_type) {
		case CKD_CPK_SIGNER_INFO:
			return (cpk_build_signer_info_object(template, ulAttrNum, new_object));

		case CKD_CPK_RECIP_INFO:
			return (cpk_build_recip_info_object(template, ulAttrNum, new_object));

		case CKD_CPK_PKCS7:
			return (cpk_build_pkcs7_object(template, ulAttrNum, new_object));

		default:
			return (CKR_DATA_TYPE_INCONSISTENT);
		}
	default:
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}
}

CK_RV
cpk_add_object(CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulCount,
	CK_ULONG *objecthandle_p, cpk_session_t *sp)
{

	CK_RV rv = CKR_OK;
	cpk_object_t *new_objp = NULL;

	new_objp = calloc(1, sizeof (cpk_object_t));
	if (new_objp == NULL) {
		return (CKR_HOST_MEMORY);
	}

	/*
	 * Validate attribute template and fill in the attributes
	 * in the cpk_object_t.
	 */
	rv = cpk_build_object(pTemplate, ulCount, new_objp);
	if (rv != CKR_OK) {
		goto fail_cleanup1;
	}

	/* Initialize the rest of stuffs in cpk_object_t. */
	(void) pthread_cond_init(&new_objp->obj_free_cond, NULL);
	(void) pthread_mutex_init(&new_objp->object_mutex, NULL);
	new_objp->magic_marker = CPKTOKEN_OBJECT_MAGIC;
	new_objp->obj_refcnt = 0;
	new_objp->obj_delete_sync = 0;

	new_objp->session_handle = (CK_SESSION_HANDLE)sp;

	/* Add the new object to the session's object list. */
	cpk_add_object_to_session(new_objp, sp);

	/* Type casting the address of an object struct to an object handle. */
	*objecthandle_p =  (CK_ULONG)new_objp;

	return (CKR_OK);

	/*
	 * When any error occurs after cpk_build_object(), we will need to
	 * clean up the memory allocated by the cpk_build_object().
	 */
	//cpk_cleanup_object(new_objp);

fail_cleanup1:
	if (new_objp) {
		/*
		 * The storage allocated inside of this object should have
		 * been cleaned up by the cpk_build_object() if it failed.
		 * Therefore, we can safely free the object.
		 */
		free(new_objp);
	}

	return (rv);

}

void
cpk_add_object_to_session(cpk_object_t *objp, cpk_session_t *sp)
{

	/* Acquire the session lock. */
	(void) pthread_mutex_lock(&sp->session_mutex);

	/* Insert the new object in front of session's object list. */
	if (sp->object_list == NULL) {
		sp->object_list = objp;
		objp->next = NULL;
		objp->prev = NULL;
	} else {
		sp->object_list->prev = objp;
		objp->next = sp->object_list;
		objp->prev = NULL;
		sp->object_list = objp;
	}

	/* Release the session lock. */
	(void) pthread_mutex_unlock(&sp->session_mutex);
}

void
cpk_cleanup_object(cpk_object_t *objp)
{
	//cpk_cleanup_extra_attr(objp);

	switch (objp->class) {
	case CKO_PUBLIC_KEY:
		CPK_IDENTITY_INFO_free(objp->object_u.identity_info);
		break;
	case CKO_PRIVATE_KEY:
		CPK_KEY_INFO_free(objp->object_u.key_info);
		break;
	}
}


/*
 * Create a new object. Copy the attributes that can be modified
 * (in the boolean attribute mask field and extra attribute list)
 * from the old object to the new object.
 *
 * The caller of this function holds the lock on the old object.
 */
CK_RV
cpk_copy_object(cpk_object_t *old_object, cpk_object_t **new_object,
    CK_ULONG object_func, cpk_session_t *sp)
{

	CK_RV rv = CKR_OK;
#if 0
	cpk_object_t *new_objp = NULL;
	CK_ATTRIBUTE_INFO_PTR attrp;

	/* Allocate new object. */
	new_objp = calloc(1, sizeof (cpk_object_t));
	if (new_objp == NULL)
		return (CKR_HOST_MEMORY);

	new_objp->class = old_object->class;
	new_objp->bool_attr_mask = old_object->bool_attr_mask;
	new_objp->cert_type = old_object->cert_type;
	new_objp->object_type = old_object->object_type;

	attrp = old_object->extra_attrlistp;
	while (attrp) {
		/*
		 * Copy the attribute_info struct from the old
		 * object to a new attribute_info struct, and add
		 * that new struct to the extra attribute list
		 * of the new object.
		 */
		rv = cpk_copy_extra_attr(attrp, new_objp);
		if (rv != CKR_OK) {
			cpk_cleanup_extra_attr(new_objp);
			free(new_objp);
			return (rv);
		}
		attrp = attrp->next;
	}

	*new_object = new_objp;

	if (object_func == CPK_SET_ATTR_VALUE) {
		/* done with copying all information that can be modified */
		return (CKR_OK);
	}

	/*
	 * Copy the rest of the object.
	 * Certain fields that are not appropriate for coping will be
	 * initialized.
	 */
	new_objp->key_type = old_object->key_type;
	new_objp->magic_marker = old_object->magic_marker;
	new_objp->mechanism = old_object->mechanism;

	switch (object_func) {
	case CPK_COPY_OBJ_ORIG_SH:
		new_objp->session_handle = old_object->session_handle;
		break;
	case CPK_COPY_OBJECT:
		/*
		 * Save the session handle of the C_CopyObject function
		 * in the new copy of the session object.
		 */
		new_objp->session_handle = (CK_SESSION_HANDLE)sp;
		break;
	}

	(void) pthread_cond_init(&(new_objp->obj_free_cond), NULL);
	(void) pthread_mutex_init(&(new_objp->object_mutex), NULL);
	/* copy key related information */
	switch (new_objp->class) {
		case CKO_PUBLIC_KEY:
			rv = cpk_copy_public_key_attr(OBJ_PUB(old_object),
			    &(OBJ_PUB(new_objp)), new_objp->key_type);
			break;
		case CKO_PRIVATE_KEY:
			rv = cpk_copy_private_key_attr(OBJ_PRI(old_object),
			    &(OBJ_PRI(new_objp)), new_objp->key_type);
			break;
		case CKO_SECRET_KEY:
			rv = cpk_copy_secret_key_attr(OBJ_SEC(old_object),
			    &(OBJ_SEC(new_objp)));
			break;
		case CKO_DOMAIN_PARAMETERS:
			rv = cpk_copy_domain_attr(OBJ_DOM(old_object),
			    &(OBJ_DOM(new_objp)), new_objp->key_type);
			break;
		case CKO_CERTIFICATE:
			rv = cpk_copy_certificate(OBJ_CERT(old_object),
			    &(OBJ_CERT(new_objp)), new_objp->cert_type);
			break;
		default:
			/* should never be this case */
			break;
	}
	if (rv != CKR_OK) {
		/*
		 * don't need to cleanup the memory from failure of copying
		 * any key related stuff.  Each individual function for
		 * copying key attr will free the memory if it fails
		 */
		cpk_cleanup_extra_attr(new_objp);
		free(new_objp);
	}
#endif
	return (rv);
}



/*
 * Remove an object from the session's object list.
 *
 * The caller of this function holds the session lock.
 */
CK_RV
cpk_remove_object_from_session(cpk_object_t *objp, cpk_session_t *sp)
{
	cpk_object_t *tmp_objp;
	boolean_t found = B_FALSE;

	/*
	 * Remove the object from the session's object list.
	 */
	if ((sp == NULL) ||
	    (sp->magic_marker != CPKTOKEN_SESSION_MAGIC)) {
		return (CKR_SESSION_HANDLE_INVALID);
	}

	if ((sp->object_list == NULL) || (objp == NULL) ||
	    (objp->magic_marker != CPKTOKEN_OBJECT_MAGIC)) {
		return (CKR_OBJECT_HANDLE_INVALID);
	}

	tmp_objp = sp->object_list;
	while (tmp_objp) {
		if (tmp_objp == objp) {
			found = B_TRUE;
			break;
		}
		tmp_objp = tmp_objp->next;
	}
	if (!found)
		return (CKR_OBJECT_HANDLE_INVALID);

	if (sp->object_list == objp) {
		/* Object is the first one in the list. */
		if (objp->next) {
			sp->object_list = objp->next;
			objp->next->prev = NULL;
		} else {
			/* Object is the only one in the list. */
			sp->object_list = NULL;
		}
	} else {
		/* Object is not the first one in the list. */
		if (objp->next) {
			/* Object is in the middle of the list. */
			objp->prev->next = objp->next;
			objp->next->prev = objp->prev;
		} else {
			/* Object is the last one in the list. */
			objp->prev->next = NULL;
		}
	}
	return (CKR_OK);
}

/*
 * This function adds the to-be-freed session object to a linked list.
 * When the number of objects queued in the linked list reaches the
 * maximum threshold MAX_OBJ_TO_BE_FREED, it will free the first
 * object (FIFO) in the list.
 */
void
object_delay_free(cpk_object_t *objp)
{
	cpk_object_t *tmp;

	(void) pthread_mutex_lock(&obj_delay_freed.obj_to_be_free_mutex);

	/* Add the newly deleted object at the end of the list */
	objp->next = NULL;
	if (obj_delay_freed.first == NULL) {
		obj_delay_freed.last = objp;
		obj_delay_freed.first = objp;
	} else {
		obj_delay_freed.last->next = objp;
		obj_delay_freed.last = objp;
	}

	if (++obj_delay_freed.count >= MAX_OBJ_TO_BE_FREED) {
		/*
		 * Free the first object in the list only if
		 * the total count reaches maximum threshold.
		 */
		obj_delay_freed.count--;
		tmp = obj_delay_freed.first->next;
		free(obj_delay_freed.first);
		obj_delay_freed.first = tmp;
	}
	(void) pthread_mutex_unlock(&obj_delay_freed.obj_to_be_free_mutex);
}

static void
cpk_delete_object_cleanup(cpk_object_t *objp)
{
	/* Acquire the lock on the object. */
	(void) pthread_mutex_lock(&objp->object_mutex);

	/*
	 * Make sure another thread hasn't freed the object.
	 */
	if (objp->magic_marker != CPKTOKEN_OBJECT_MAGIC) {
		(void) pthread_mutex_unlock(&objp->object_mutex);
		return;
	}

	/*
	 * The deletion of an object must be blocked when the object
	 * reference count is not zero. This means if any object related
	 * operation starts prior to the delete object operation gets in,
	 * the object deleting thread must wait for the non-deleting
	 * operation to be completed before it can proceed the delete
	 * operation.
	 */
	while (objp->obj_refcnt != 0) {
		/*
		 * We set the OBJECT_REFCNT_WAITING flag before we put
		 * this deleting thread in a wait state, so other non-deleting
		 * operation thread will signal to wake it up only when
		 * the object reference count becomes zero and this flag
		 * is set.
		 */
		objp->obj_delete_sync |= OBJECT_REFCNT_WAITING;
		(void) pthread_cond_wait(&objp->obj_free_cond,
			&objp->object_mutex);
	}

	objp->obj_delete_sync &= ~OBJECT_REFCNT_WAITING;

	/* Mark object as no longer valid. */
	objp->magic_marker = 0;

	(void) pthread_cond_destroy(&objp->obj_free_cond);

	/*
	 * Cleanup the contents of this object such as free all the
	 * storage allocated for this object.
	 */
	cpk_cleanup_object(objp);

	/* Reset OBJECT_IS_DELETING flag. */
	objp->obj_delete_sync &= ~OBJECT_IS_DELETING;

	(void) pthread_mutex_unlock(&objp->object_mutex);
	/* Destroy the object lock */
	(void) pthread_mutex_destroy(&objp->object_mutex);

	/*
	 * Delay freeing the session object as S1WS/NSS uses session
	 * objects for its SSL Handshake.
	 */
	(void) object_delay_free(objp);

}

/*
 * Delete an object:
 * - Remove the object from the session's object list.
 *   Holding the lock on the session which the object was created at
 *   is needed to do this.
 * - Release the storage allocated to the object.
 *
 * The boolean argument lock_held is used to indicate that whether
 * the caller holds the session lock or not.
 * - When called by cpk_delete_all_objects_in_session() -- the
 *   lock_held = TRUE.
 *
 * When the caller does not hold the session lock, this function
 * will acquire that lock in order to proceed, and also release
 * that lock before returning to caller.
 */
void
cpk_delete_object(cpk_session_t *sp, cpk_object_t *objp, boolean_t lock_held)
{

	/*
	 * Check to see if the caller holds the lock on the session.
	 * If not, we need to acquire that lock in order to proceed.
	 */
	if (!lock_held) {
		/* Acquire the session lock. */
		(void) pthread_mutex_lock(&sp->session_mutex);
	}

	/* Remove the object from the session's object list first. */
	if (cpk_remove_object_from_session(objp, sp) != CKR_OK) {
		if (!lock_held) {
			(void) pthread_mutex_unlock(&sp->session_mutex);
		}
		return;
	}

	if (!lock_held) {
		/*
		 * If the session lock is obtained by this function,
		 * then release that lock after removing the object
		 * from session's object list.
		 * We want the releasing of the object storage to
		 * be done without holding the session lock.
		 */
		(void) pthread_mutex_unlock(&sp->session_mutex);
	}

	cpk_delete_object_cleanup(objp);
}


/*
 * Delete all the objects in a session. The caller holds the lock
 * on the session.
 */
void
cpk_delete_all_objects_in_session(cpk_session_t *sp)
{
	cpk_object_t *objp = sp->object_list;
	cpk_object_t *objp1;

	/* Delete all the objects in the session. */
	while (objp) {
		objp1 = objp->next;

		/*
		 * Delete an object by calling cpk_delete_object()
		 * with a TRUE boolean argument indicating that
		 * the caller holds the lock on the session.
		 */
		cpk_delete_object(sp, objp, B_TRUE);

		objp = objp1;
	}
}



/*
 * Insert an object into a list of cpk_object_t objects.  It is assumed
 * that the object to be inserted doesn't previously belong to any list
 */
static void
insert_into_list(cpk_object_t **list, cpk_object_t **end_of_list,
    cpk_object_t *objp)
{
	if (*list == NULL) {
		*list = objp;
		objp->next = NULL;
		objp->prev = NULL;
		*end_of_list = objp;
	} else {
		(*list)->prev = objp;
		objp->next = *list;
		objp->prev = NULL;
		*list = objp;
	}
}

/*
 * Move an object from an existing list into a new list of
 * cpk_object_t objects.
 */
static void
move_into_list(cpk_object_t **existing_list, cpk_object_t **new_list,
    cpk_object_t **end_of_list, cpk_object_t *objp)
{

	/* first, remove object from existing list */
	if (objp == *existing_list) {
		/* first item in list */
		if (objp->next) {
			*existing_list = objp->next;
			objp->next->prev = NULL;
		} else {
			*existing_list = NULL;
		}
	} else {
		if (objp->next) {
			objp->prev->next = objp->next;
			objp->next->prev = objp->prev;
		} else {
			objp->prev->next = NULL;
		}
	}

	/* then, add into new list */
	insert_into_list(new_list, end_of_list, objp);
}

/*
 * Insert "new_list" into "existing_list", new list will always be inserted
 * into the front of existing list
 */
static void
insert_list_into_list(cpk_object_t **existing_list,
    cpk_object_t *new_list, cpk_object_t *end_new_list)
{

	if (new_list == NULL) {
		return;
	}

	if (*existing_list == NULL) {
		*existing_list = new_list;
	} else {
		(*existing_list)->prev = end_new_list;
		end_new_list->next = *existing_list;
		*existing_list = new_list;
	}
}

static void
delete_all_objs_in_list(cpk_object_t *list)
{
	cpk_object_t *objp, *objp_next;

	if (list == NULL) {
		return;
	}

	objp = list;
	while (objp) {
		objp_next = objp->next;
		cpk_delete_object_cleanup(objp);
		objp = objp_next;
	}
}

