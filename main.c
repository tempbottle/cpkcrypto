#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include "pkcs11cpk.h"
#include "cpkPlatform.h"


#define PUBLIC_MATRIX_FILE_NAME		"keystore" PATH_SEP "public_matrix.cpk"
#define PUBLIC_MATRIX_BUFFER_SIZE	(1024*64)

#define PRIVATE_KEY_FILE_NAME		"keystore" PATH_SEP "key_info.cpk"
#define PRIVATE_KEY_BUFFER_SIZE		(1024*64)

int main()
{
	
	/* 
	 * public matrix and private key are decoded from file,
	 * the CPK PKCS#11 does not provide key generation methods
	 * at current version, but will be added later.
	 */
	CK_BYTE_PTR publicMatrixBuffer = NULL_PTR;
	CK_ULONG publicMatrixLen = 0;
	FILE *publicMatrixFp = NULL_PTR;

	CK_BYTE_PTR privateKeyBuffer = NULL_PTR;
	CK_ULONG privateKeyLen = 0;
	FILE *privateKeyFp = NULL_PTR;


	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_KEY_TYPE keyType = CKK_CPK;
	CK_KEY_TYPE matrixType = CKK_CPK_MATRIX;

	/* buffer for decrypted data */
	CK_BYTE_PTR pBuffer = NULL_PTR; 
	CK_ULONG ulBufferLen = 0;

	/*
	 * CPK PKCS#11 use CPK_KEY_INFO as private key object,
	 * build from CPK_KEY_INFO DER-encoding file
	 * the private key object is used to sign and decrypt
	 */
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_CPK_DER, NULL, 0},
	};
	CK_OBJECT_HANDLE hPrivateKey;

	/* 
	 * CPK PKCS#11 use CPK_IDENTITY_INFO with inner public matrix
	 * as the PKCS#11 public key object, we need the DER-encoding of
	 * CPK_PUBLIC_MATRIX and a specified CPK identity.
	 * the public key object is only used to encrypt.
	 */
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE publicKeyTemplate[] ={
		{CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_CPK_DER, NULL_PTR, 0},
		{CKA_CPK_ID, "guanzhi", strlen("guanzhi")},
	};
	CK_OBJECT_HANDLE hPublicKey;

	/*
	 * public matrix object is only used to verify signature.
	 */
	CK_ATTRIBUTE publicMatrixTemplate[] = {
		{CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass)},
		{CKA_KEY_TYPE, &matrixType, sizeof(matrixType)},
		{CKA_CPK_DER, NULL_PTR, 0},
	};
	CK_OBJECT_HANDLE hPublicMatrix;


	/* cpk encryption mechanism */
	CK_BYTE pEncryptedData[4096];
	CK_ULONG ulEncryptedDataLen = 4096;
	CK_MECHANISM encryptMechanism = {
		CKM_CPK_ECIES_STDDH_SHA1KDF_AES128CBC_PAD_SHA1HMAC, NULL_PTR, 0
	};

	/* cpk sign mechanism */
	CK_BYTE pSignature[4096];
	CK_ULONG ulSignatureLen = 4096;
	CK_MECHANISM signMechanism = { CKM_CPK_ECDSA_SHA1, NULL_PTR, 0 };


	/* read DER-encoding of public matrix from file */
	publicMatrixFp = fopen(PUBLIC_MATRIX_FILE_NAME, "rb");
	assert(publicMatrixFp != NULL_PTR);
	
	publicMatrixBuffer = (CK_BYTE_PTR)malloc(PUBLIC_MATRIX_BUFFER_SIZE);
	assert(publicMatrixBuffer != NULL_PTR);
	
	publicMatrixLen = (CK_ULONG)fread(publicMatrixBuffer, 1,
		PUBLIC_MATRIX_BUFFER_SIZE, publicMatrixFp);
	assert(publicMatrixLen > 0);

	/* read DER-encoding of private key from file */
	privateKeyFp = fopen(PRIVATE_KEY_FILE_NAME, "rb");
	assert(privateKeyFp != NULL_PTR);

	privateKeyBuffer = (CK_BYTE_PTR)malloc(PRIVATE_KEY_BUFFER_SIZE);
	assert(privateKeyBuffer != NULL_PTR);

	privateKeyLen = (CK_ULONG)fread(privateKeyBuffer, 1, 
		PRIVATE_KEY_BUFFER_SIZE, privateKeyFp);
	assert(privateKeyLen > 0);


	/* finish the setting of object templates */
	privateKeyTemplate[2].pValue = privateKeyBuffer;
	privateKeyTemplate[2].ulValueLen = privateKeyLen;

	publicKeyTemplate[2].pValue = publicMatrixBuffer;
	publicKeyTemplate[2].ulValueLen = publicMatrixLen;

	publicMatrixTemplate[2].pValue = publicMatrixBuffer;
	publicMatrixTemplate[2].ulValueLen = publicMatrixLen;




	/* initialize PKCS#11 library */
	rv = C_Initialize(NULL_PTR);
	assert(rv == CKR_OK);
	
	rv = C_OpenSession(8, 0xffffffff, NULL_PTR, NULL_PTR, &hSession);
	assert(rv == CKR_OK);

	/* create objects */
	rv = C_CreateObject(hSession, privateKeyTemplate, 
		sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE), &hPrivateKey);
	assert(rv == CKR_OK);

	rv = C_CreateObject(hSession, publicKeyTemplate,
		sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE), &hPublicKey);
	assert(rv == CKR_OK);

	rv = C_CreateObject(hSession, publicMatrixTemplate,
		sizeof(publicMatrixTemplate)/sizeof(CK_ATTRIBUTE),
		&hPublicMatrix);


	/*
	 * encrypt with public key object and 
	 * decrypt with private key object
	 */ 
	rv = C_EncryptInit(hSession, &encryptMechanism, hPublicKey);
	assert(rv == CKR_OK);

	rv = C_Encrypt(hSession, (CK_BYTE_PTR)"plaintext", sizeof("plaintext"),
		pEncryptedData, &ulEncryptedDataLen);
	assert(rv == CKR_OK);

	rv = C_DecryptInit(hSession, &encryptMechanism, hPrivateKey);
	assert(rv == CKR_OK);

	ulBufferLen = 8096;
	pBuffer = (CK_BYTE_PTR)malloc(ulBufferLen);
	assert(pBuffer != NULL_PTR);

	rv = C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pBuffer,
		&ulBufferLen);
	assert(rv == CKR_OK);

	/* check if decrypted data equals to encrypted data */
	assert(ulBufferLen == sizeof("plaintext"));
	assert(memcmp("plaintext", pBuffer, ulBufferLen) == 0);



	/*
	 * sign with private key object and
	 * verify with public matrix object
	 */
	rv = C_SignInit(hSession, &signMechanism, hPrivateKey);
	assert(rv == CKR_OK);

	rv = C_SignUpdate(hSession, "tobesigned", sizeof("tobesigned"));
	assert(rv == CKR_OK);

	rv = C_SignFinal(hSession, pSignature, &ulSignatureLen);
	assert(rv == CKR_OK);

	rv = C_VerifyInit(hSession, &signMechanism, hPublicMatrix);
	assert(rv == CKR_OK);

	rv = C_VerifyUpdate(hSession, "tobesigned", sizeof("tobesigned"));
	assert(rv == CKR_OK);

	rv = C_VerifyFinal(hSession, pSignature, ulSignatureLen);
	assert(rv == CKR_OK);

	printf("ok\n");


	/*
	 * we will show some details of the signature
	 */
	{
		CK_OBJECT_HANDLE hSignature;

		CK_OBJECT_CLASS dataClass = CKO_DATA;
		CK_DATA_TYPE dataType = CKD_CPK_SIGNER_INFO;
		CK_ATTRIBUTE signatureTemplate[] = {
			{CKA_CLASS, &dataClass, sizeof(dataClass)},
			{CKA_DATA_TYPE, &dataType, sizeof(dataType)},
			{CKA_CPK_DER, pSignature, ulSignatureLen},
		};

		CK_BYTE signerId[256];
		CK_BYTE matrixUri[256];
		CK_ATTRIBUTE signerInfoTemplate[] = {
			{CKA_CPK_SIGNER_ID, signerId, sizeof(signerId)},
			{CKA_CPK_MATRIX_URI, matrixUri, sizeof(matrixUri)},		
		};
		memset(signerId, 0, sizeof(signerId));
		memset(matrixUri, 0, sizeof(matrixUri));

		rv = C_CreateObject(hSession, signatureTemplate, 3, &hSignature);
		assert(rv == CKR_OK);

		rv = C_GetAttributeValue(hSession, hSignature, signerInfoTemplate, 2);
		assert(rv == CKR_OK);

		printf("signer id = %s\n", signerId);
		printf("matrix uri = %s\n", matrixUri);
	}

	return 0;



}
