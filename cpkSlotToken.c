#include <stdlib.h>
#include <string.h>
#include <security/cryptoki.h>
#include "pkcs11cpk.h"
#include "cpkGlobal.h"
#include "cpkSession.h"
#include "cpkObject.h"
#include "cpkPkcs11.h"

#define CKM_CPK							0x80000002
#define CKM_CPK_ECDSA						0x80000003
#define CKM_CPK_ECDSA_SHA1					0x80000004
#define CKM_CPK_ECIES						0x80000005
#define CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_MD5HMAC		0x80000016
#define CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_SHA1HMAC	0x80000006
#define CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CBC_PAD_SHA1HMAC	0x80000007
#define CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CFB_SHA1HMAC		0x80000017
#define CKM_CPK_PKCS7_SIGNED					0x80000008
#define CKM_CPK_PKCS7_ENVELOPE_DES3CBC_PAD			0x80000009
#define CKM_CPK_PKCS7_ENVELOPE_AES128CBC_PAD			0x8000000a
#define CKM_CPK_PKCS7_SIGNED_ENVELOPED_DES3CBC_PAD		0x8000000b
#define CKM_CPK_PKCS7_SIGNED_ENVELOPED_AES128CBC_PAD		0x8000000c
#define CKM_CPK_PKCS7						0x8000000d


static CK_MECHANISM_TYPE cpk_mechanisms[] = {
	CKM_CPK,
	CKM_CPK_ECDSA,
	CKM_CPK_ECDSA_SHA1,
	CKM_CPK_ECIES,
	CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_MD5HMAC,
	CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_SHA1HMAC,
	CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CBC_PAD_SHA1HMAC,
	CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CFB_SHA1HMAC,
	CKM_CPK_PKCS7_SIGNED,
	CKM_CPK_PKCS7_ENVELOPE_DES3CBC_PAD,
	CKM_CPK_PKCS7_ENVELOPE_AES128CBC_PAD,
	CKM_CPK_PKCS7_SIGNED_ENVELOPED_DES3CBC_PAD,
	CKM_CPK_PKCS7_SIGNED_ENVELOPED_AES128CBC_PAD,
};

static CK_MECHANISM_INFO cpk_mechanism_info[] = {
	{128,521,CKF_SIGN|CKF_VERIFY|CKF_ENCRYPT|CKF_DECRYPT},	/* CKM_CPK */
	{128,521,CKF_SIGN|CKF_VERIFY},		/* CKM_CPK_ECDSA */
	{128,521,CKF_SIGN|CKF_VERIFY},		/* CKM_CPK_ECDSA_SHA1 */
	{128,521,CKF_ENCRYPT|CKF_DECRYPT},	/* CKM_CPK_ECIES */
	{128,521,CKF_ENCRYPT|CKF_DECRYPT},	/* CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_MD5HMAC */
	{128,521,CKF_ENCRYPT|CKF_DECRYPT},	/* CKM_CPK_ECIES_STDDH_SHA1KDF_DES3CBC_PAD_SHA1HMAC */
	{128,521,CKF_ENCRYPT|CKF_DECRYPT},	/* CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CBC_PAD_SHA1HMAC */
	{128,521,CKF_ENCRYPT|CKF_DECRYPT},	/* CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CFB_SHA1HMAC */
	{128,521,CKF_SIGN|CKF_VERIFY|
		CKF_SIGN_RECOVER|CKF_VERIFY_RECOVER},
						/* CKM_CPK_PKCS7_SIGNED */
	{128,521,CKF_ENCRYPT|CKF_DECRYPT},	/* CKM_CPK_PKCS7_ENVELOPE_DES3CBC_PAD */
	{128,521,CKF_ENCRYPT|CKF_DECRYPT},	/* CKM_CPK_PKCS7_ENVELOPE_AES128CBC_PAD */
	{128,521,CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|CKF_VERIFY|
		CKF_SIGN_RECOVER|CKF_VERIFY_RECOVER},	
						/* CKM_CPK_PKCS7_SIGNED_ENVELOPED_DES3CBC_PAD */
	{128,521,CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|CKF_VERIFY|
		CKF_SIGN_RECOVER|CKF_VERIFY_RECOVER},
						/* CKM_CPK_PKCS7_SIGNED_ENVELOPED_AES128CBC_PAD */
};

CK_RV
C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount)
{

	CK_RV rv;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pulCount == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	if (pSlotList == NULL) {
		/*
		 * Application only wants to know the number of slots.
		 */
		*pulCount = 1;
		return (CKR_OK);
	}

	if ((*pulCount < 1) && (pSlotList != NULL)) {
		rv = CKR_BUFFER_TOO_SMALL;
	} else {
		pSlotList[0] = CPKTOKEN_SLOTID;
		rv = CKR_OK;
	}

	*pulCount = 1;
	return (rv);
}


CK_RV
C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Make sure the slot ID is valid */
	if (slotID != CPKTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	/* Provide information about the slot in the provided buffer */
	(void) strncpy((char *)pInfo->slotDescription, CPK_SLOT_DESCRIPTION,
	    64);
	(void) strncpy((char *)pInfo->manufacturerID, CPK_MANUFACTURER_ID, 32);
	pInfo->flags = 0;
	pInfo->flags |= CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = HARDWARE_VERSION_MAJOR;
	pInfo->hardwareVersion.minor = HARDWARE_VERSION_MINOR;
	pInfo->firmwareVersion.major = FIRMWARE_VERSION_MAJOR;
	pInfo->firmwareVersion.minor = FIRMWARE_VERSION_MINOR;

	return (CKR_OK);
}


CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{

	ulong_t	token_flag = 0;
	boolean_t pin_initialized = B_FALSE;
	char	*ks_cryptpin = NULL;
	CK_RV rv = CKR_OK;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Make sure the slot ID is valid */
	if (slotID != CPKTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Provide information about a token in the provided buffer */
	(void) strncpy((char *)pInfo->label, CPK_TOKEN_LABEL, 32);
	(void) strncpy((char *)pInfo->manufacturerID, CPK_MANUFACTURER_ID, 32);
	(void) strncpy((char *)pInfo->model, TOKEN_MODEL, 16);
	(void) strncpy((char *)pInfo->serialNumber, CPK_TOKEN_SERIAL, 16);

	pInfo->flags = token_flag;
	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = cpk_session_cnt;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulRwSessionCount = cpk_session_rw_cnt;
	pInfo->ulMaxPinLen = MAX_PIN_LEN;
	pInfo->ulMinPinLen = MIN_PIN_LEN;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = HARDWARE_VERSION_MAJOR;
	pInfo->hardwareVersion.minor = HARDWARE_VERSION_MINOR;
	pInfo->firmwareVersion.major = FIRMWARE_VERSION_MAJOR;
	pInfo->firmwareVersion.minor = FIRMWARE_VERSION_MINOR;
	(void) memset(pInfo->utcTime, ' ', 16);

	return (CKR_OK);
}

/*ARGSUSED*/
CK_RV
C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}


CK_RV
C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount)
{

	ulong_t i;
	ulong_t mechnum;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != CPKTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	mechnum = sizeof (cpk_mechanisms) / sizeof (CK_MECHANISM_TYPE);

	if (pMechanismList == NULL) {
		/*
		 * Application only wants to know the number of
		 * supported mechanism types.
		 */
		*pulCount = mechnum;
		return (CKR_OK);
	}

	if (*pulCount < mechnum) {
		*pulCount = mechnum;
		return (CKR_BUFFER_TOO_SMALL);
	}

	for (i = 0; i < mechnum; i++) {
		pMechanismList[i] = cpk_mechanisms[i];
	}

	*pulCount = mechnum;

	return (CKR_OK);
}


CK_RV
C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo)
{

	ulong_t i;
	ulong_t mechnum;

	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != CPKTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	if (pInfo == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	mechnum = sizeof (cpk_mechanisms) / sizeof (CK_MECHANISM_TYPE);
	for (i = 0; i < mechnum; i++) {
		if (cpk_mechanisms[i] == type)
			break;
	}

	if (i == mechnum)
		/* unsupported mechanism */
		return (CKR_MECHANISM_INVALID);

	pInfo->ulMinKeySize = cpk_mechanism_info[i].ulMinKeySize;
	pInfo->ulMaxKeySize = cpk_mechanism_info[i].ulMaxKeySize;
	pInfo->flags = cpk_mechanism_info[i].flags;

	return (CKR_OK);
}


/*ARGSUSED*/
CK_RV
C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
    CK_UTF8CHAR_PTR pLabel)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

/*ARGSUSED*/
CK_RV
C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}


CK_RV
C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldPinLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen)
{
	if (!cpktoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}
