#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include "pkcs11cpk.h"
#include "cpkObject.h"
#include "cpkOps.h"
#include "cpkSession.h"
#include "cpkPkcs11.h"


CK_RV
cpk_verify_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p)
{

	switch (pMechanism->mechanism) {
	
	case CKM_CPK:
	case CKM_CPK_ECDSA:
	case CKM_CPK_ECDSA_SHA1:
		return (si_verify_init(session_p, pMechanism, key_p));

	default:
		return (CKR_MECHANISM_INVALID);
	}

}


CK_RV
cpk_verify(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->verify.mech.mechanism;

	switch (mechanism) {

	case CKM_CPK:
	case CKM_CPK_ECDSA:
	case CKM_CPK_ECDSA_SHA1:
		return (si_verify(session_p, pData, ulDataLen, pSignature,
		    ulSignatureLen));

	default:
		return (CKR_MECHANISM_INVALID);
	}
}

CK_RV
cpk_verify_update(cpk_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	CK_MECHANISM_TYPE mechanism = session_p->verify.mech.mechanism;

	switch (mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECDSA:
	case CKM_CPK_ECDSA_SHA1:
		return (si_verify_update(session_p, pPart, ulPartLen));

	default:
		/* PKCS11: The mechanism only supports single-part operation. */
		return (CKR_MECHANISM_INVALID);
	}
}

CK_RV
cpk_verify_final(cpk_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->verify.mech.mechanism;
	CK_RV rv = CKR_OK;

	switch (mechanism) {
	case CKM_CPK:
	case CKM_CPK_ECDSA:
	case CKM_CPK_ECDSA_SHA1:
		return (si_verify_final(session_p, pSignature, ulSignatureLen));
		

	default:
		/* PKCS11: The mechanism only supports single-part operation. */
		return (CKR_MECHANISM_INVALID);

	}
}
