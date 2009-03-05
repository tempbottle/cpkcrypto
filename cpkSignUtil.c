#include <stdlib.h>
#include <security/cryptoki.h>
#include "pkcs11cpk.h"
#include "cpkObject.h"
#include "cpkSession.h"
#include "cpkPkcs11.h"
#include "cpkOps.h"

CK_RV
cpk_sign_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p)
{

	switch (pMechanism->mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECDSA:
	case CKM_CPK_ECDSA_SHA1:
		return (si_sign_init(session_p, pMechanism, key_p));
	default:
		return (CKR_MECHANISM_INVALID);
	}

}


CK_RV
cpk_sign(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->sign.mech.mechanism;

	switch (mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECDSA:
	case CKM_CPK_ECDSA_SHA1:
		return (si_sign(session_p, pData, ulDataLen, pSignature,
		    pulSignatureLen));
	default:
		return (CKR_MECHANISM_INVALID);
	}

}


CK_RV
cpk_sign_update(cpk_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	CK_MECHANISM_TYPE	mechanism = session_p->sign.mech.mechanism;

	switch (mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECDSA:
	case CKM_CPK_ECDSA_SHA1:
		return (si_sign_update(session_p, pPart, ulPartLen));
	
	default:
		return (CKR_MECHANISM_INVALID);
	}
}


CK_RV
cpk_sign_final(cpk_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->sign.mech.mechanism;

	switch (mechanism) {
	case CKM_CPK_ECDSA_SHA1:
		return (si_sign_final(session_p, pSignature, pulSignatureLen));
	default:
		return (CKR_MECHANISM_INVALID);
	}

}

void
cpk_sign_verify_cleanup(cpk_session_t *session_p, boolean_t sign,
    boolean_t lock_held)
{

	crypto_active_op_t *active_op;
	boolean_t lock_true = B_TRUE;

	if (!lock_held)
		(void) pthread_mutex_lock(&session_p->session_mutex);

	active_op = (sign) ? &(session_p->sign) : &(session_p->verify);

	switch (active_op->mech.mechanism) {
	case CKM_CPK_ECDSA:
	case CKM_CPK_ECDSA_SHA1:
		si_sign_verify_cleanup(session_p, sign);
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
