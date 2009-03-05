#ifndef _CPKOPS_H
#define	_CPKOPS_H


#ifdef __cplusplus
extern "C" {
#endif

#include <security/pkcs11t.h>
#include "cpkObject.h"
#include "cpkSession.h"


/*
 * Function Prototypes.
 */
void cpk_init_library(void);

CK_RV cpk_sign_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p);

CK_RV cpk_sign(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen);

CK_RV cpk_sign_update(cpk_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen);

CK_RV cpk_sign_final(cpk_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen);

void cpk_sign_verify_cleanup(cpk_session_t *session_p, boolean_t sign,
    boolean_t lock_held);

CK_RV cpk_verify_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p);

CK_RV cpk_verify(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen);

CK_RV cpk_verify_update(cpk_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen);

CK_RV cpk_verify_final(cpk_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen);


/* cpkEncryptUtil.c */
CK_RV cpk_encrypt_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p);

CK_RV cpk_encrypt(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen);

void cpk_crypt_cleanup(cpk_session_t *session_p, boolean_t encrypt,
    boolean_t lock_held);

/* cpkDecryptUtil.c */
CK_RV cpk_decrypt_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p);

CK_RV cpk_decrypt_common(cpk_session_t *session_p, CK_BYTE_PTR pEncrypted,
    CK_ULONG ulEncryptedLen, CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen, boolean_t Update);

CK_RV cpk_decrypt(cpk_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen);

/* cpkSignUtil.c */
CK_RV cpk_sign_init(cpk_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    cpk_object_t *key_p);

CK_RV cpk_sign(cpk_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen);

CK_RV cpk_sign_update(cpk_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen);

CK_RV cpk_sign_final(cpk_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen);

void cpk_sign_verify_cleanup(cpk_session_t *session_p, boolean_t sign,
    boolean_t lock_held);



#ifdef	__cplusplus
}
#endif

#endif /* _CPKOPS_H */
