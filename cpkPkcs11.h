#ifndef _CPKPKCS11_H
#define _CPKPKCS11_H

#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include "cpkObject.h"



void cpk_init_library(void);

CK_RV cpk_build_public_key_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum, cpk_object_t *new_object);

CK_RV cpk_build_private_key_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object);

CK_RV cpk_build_public_matrix_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object);

CK_RV cpk_build_signer_info_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object);

CK_RV cpk_build_recip_info_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object);

CK_RV cpk_build_pkcs7_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	cpk_object_t *new_object);

void cpk_cleanup_public_key_object(cpk_object_t *object_p);

void cpk_cleanup_private_key_object(cpk_object_t *object_p);

CK_RV cpk_set_public_key_attribute(cpk_object_t *object_p,
	CK_ATTRIBUTE_PTR template, boolean_t copy);

CK_RV si_sign_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p);

CK_RV si_verify_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p);

CK_RV si_sign_update(cpk_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen);

CK_RV si_verify_update(cpk_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen);

CK_RV si_sign_final(cpk_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen);

CK_RV si_sign(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen);

CK_RV si_verify(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen);

CK_RV si_verify_final(cpk_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen);

void si_sign_verify_cleanup(cpk_session_t *session_p, boolean_t sign);

CK_RV ri_encrypt_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
	cpk_object_t *key_p);

CK_RV ri_encrypt(cpk_session_t *session_p, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncrypted, CK_ULONG_PTR pulEncryptedLen);

CK_RV ri_decrypt_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p);

CK_RV ri_decrypt(cpk_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen);

#endif
