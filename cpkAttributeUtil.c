#include <stdlib.h>
#include <string.h>
#include <openssl/objects.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include "cpkObject.h"
#include "cpkGlobal.h"
#include "cpkPlatform.h"
#include "pkcs11cpk.h"


CK_RV
get_string_attr_from_object(CK_BYTE_PTR pValue, CK_ULONG ulValueLen, CK_ATTRIBUTE_PTR template)
{
	if (pValue == NULL_PTR || ulValueLen == 0)
		return (CKR_GENERAL_ERROR);

	if (template->pValue == NULL) {
		template->ulValueLen = ulValueLen;
		return (CKR_OK);
	}
	
	if (template->ulValueLen >= ulValueLen) {
		memcpy(template->pValue, pValue, ulValueLen);
		template->ulValueLen = ulValueLen;
		return (CKR_OK);
	} else {
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_BUFFER_TOO_SMALL);
	}
}

CK_RV
get_ulong_attr_from_object(CK_ULONG value, CK_ATTRIBUTE_PTR template)
{
	if (template->pValue == NULL) {
		template->ulValueLen = sizeof (CK_ULONG);
		return (CKR_OK);
	}

	if (template->ulValueLen >= sizeof (CK_ULONG)) {
		*((CK_ULONG_PTR)template->pValue) = value;
		template->ulValueLen = sizeof (CK_ULONG);
		return (CKR_OK);
	} else {
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_BUFFER_TOO_SMALL);
	}
}

CK_RV
get_bool_attr(CK_BBOOL value, CK_ATTRIBUTE_PTR template)
{
	if (template->pValue == NULL) {
		template->ulValueLen = sizeof (CK_BBOOL);
		return (CKR_OK);
	}

	if (template->ulValueLen >= sizeof (CK_BBOOL)) {
		if (value == CK_TRUE) {
			*((CK_BBOOL *)template->pValue) = CK_TRUE;
		} else {
			*((CK_BBOOL *)template->pValue) = CK_FALSE;
		}
		template->ulValueLen = sizeof (CK_BBOOL);
		return (CKR_OK);
	} else {
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_BUFFER_TOO_SMALL);
	}
}

CK_RV cpk_get_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{

	CK_RV rv = CKR_OK;
	CK_OBJECT_CLASS class = object_p->class;

	switch (class) {
	case CKO_PUBLIC_KEY:
		rv = cpk_get_public_key_attribute(object_p, template);
		break;

	case CKO_PRIVATE_KEY:
		rv = cpk_get_private_key_attribute(object_p, template);
		break;

	case CKO_DATA:
		rv = cpk_get_data_attribute(object_p, template);
		break;

	default:
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	return (rv);
}

CK_RV
cpk_get_public_key_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	CK_RV rv = CKR_OK;

	switch (object_p->key_type) {
	case CKK_CPK:
		rv = cpk_get_key_info_attribute(object_p, template);
		break;

	case CKK_CPK_MATRIX:
		rv = cpk_get_public_matrix_attribute(object_p, template);
		break;

	default:
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	return (rv);
}

CK_RV
cpk_get_private_key_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	CK_RV rv = CKR_OK;

	switch (object_p->key_type) {
	case CKK_CPK:
		rv = cpk_get_key_info_attribute(object_p, template);
		break;

	case CKK_CPK_MATRIX:
		rv = cpk_get_secret_matrix_attribute(object_p, template);
		break;

	default:
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	return (rv);
}

CK_RV
cpk_get_data_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	CK_RV rv = CKR_OK;

	switch (object_p->data_type) {
	case CKD_CPK_SIGNER_INFO:
		rv = cpk_get_signer_info_attribute(object_p, template);
		break;

	case CKD_CPK_RECIP_INFO:
		rv = cpk_get_recip_info_attribute(object_p, template);
		break;

	case CKD_CPK_PKCS7:
		rv = cpk_get_pkcs7_attribute(object_p, template);
		break;

	default:
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	return (rv);
}


CK_RV
cpk_get_signer_info_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	CPK_SIGNER_INFO *signer_info = object_p->object_u.signer_info;

	if (signer_info == NULL_PTR)
		return (CKR_ARGUMENTS_BAD);

	switch (template->type) {
	case CKA_CPK_SIGNER_ID:
		if (signer_info->signer == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);
		if (signer_info->signer->id_data == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);
		if (signer_info->signer->id_data->data == NULL_PTR ||
		    signer_info->signer->id_data->length <= 0)
			return (CKR_ARGUMENTS_BAD);

		return get_string_attr_from_object(
		    (CK_BYTE_PTR)(signer_info->signer->id_data->data),
		    (CK_ULONG)(signer_info->signer->id_data->length),
		    template);

	case CKA_CPK_MATRIX_URI:
		if (signer_info->signer == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);
		if (signer_info->signer->matrix_uri == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);

		return (get_string_attr_from_object(
		    (CK_BYTE_PTR)(signer_info->signer->matrix_uri->data),
		    (CK_ULONG)(signer_info->signer->matrix_uri->length),
		    template));

	case CKA_CPK_DIGEST_MECHANISM:
	{
		const EVP_MD *md = NULL_PTR;
		CK_MECHANISM_PTR pMechanism = NULL_PTR;

		if (template->pValue == NULL) {
			template->ulValueLen = sizeof(CK_MECHANISM);
			return (CKR_OK);
		} 
		if (template->ulValueLen < sizeof(CK_MECHANISM)) {
			template->ulValueLen = sizeof(CK_MECHANISM);
			return (CKR_BUFFER_TOO_SMALL);
		}

		if (signer_info->digest_algor == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);
		
		md = EVP_get_digestbynid(OBJ_obj2nid(signer_info->digest_algor->algorithm));
		if (md == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);
		
		if (md != EVP_sha1())	
			return (CKR_ARGUMENTS_BAD);
		
		pMechanism = (CK_MECHANISM_PTR)(template->pValue);
		pMechanism->mechanism = CKM_SHA_1;
		pMechanism->pParameter = NULL_PTR;
		pMechanism->ulParameterLen = 0;
		
		break;
	}
	case CKA_CPK_SIGN_MECHANISM:
		return 0;
	case CKA_CPK_SIGNED_TIME:
	{
		return (CKR_GENERAL_ERROR);
	}
	case CKA_CPK_DER:
	{
		return (CKR_GENERAL_ERROR);
	}
	default:
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}
}

CK_RV
cpk_get_recip_info_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	CK_RV rv = CKR_OK;
	CPK_RECIP_INFO *recip_info = object_p->object_u.recip_info;

	if (recip_info == NULL_PTR)
		return (CKR_ARGUMENTS_BAD);

	switch (template->type) {
	case CKA_CPK_ID:
		if (recip_info->recipient == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);
		if (recip_info->recipient->id_data == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);
		return (get_string_attr_from_object(
		    (CK_BYTE_PTR)(recip_info->recipient->id_data->data),
		    (CK_ULONG)(recip_info->recipient->id_data->length),
		    template));

	case CKA_CPK_MATRIX_URI:
		if (recip_info->recipient == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);
		if (recip_info->recipient->matrix_uri == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);
		return (get_string_attr_from_object(
		    (CK_BYTE_PTR)(recip_info->recipient->matrix_uri->data),
		    (CK_ULONG)(recip_info->recipient->matrix_uri->length),
		    template));
	//	
	//case CKA_CPK_ENCRYPT_MECHANISM:
	//
	//case CKA_CPK_ECIES_PARAMETERS:

	//	break;
	default:
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}
}

CK_RV
cpk_get_pkcs7_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	return (CKR_GENERAL_ERROR);
}

CK_RV
cpk_get_public_matrix_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	CK_RV rv = CKR_OK;
	CPK_PUBLIC_MATRIX *matrix = object_p->object_u.public_matrix;

	if (matrix == NULL_PTR)
		return (CKR_ARGUMENTS_BAD);

	switch (template->type) {
	case CKA_CPK_MATRIX_URI:
	case CKA_CPK_EC_NAME:
	{
		const char *ec_name = OBJ_nid2sn(OBJ_obj2nid(matrix->curve_obj));
		size_t ec_name_len = strlen(ec_name);
	
	}
	case CKA_CPK_MATRIX_COLUMN:
	{

	}
	case CKA_CPK_MATRIX_ROW:
	{
		CK_ULONG matrix_row = matrix->row_size;

		if (template->pValue == NULL) {
			template->ulValueLen = sizeof(CK_ULONG);
			return (CKR_OK);
		} else if (template->ulValueLen >= sizeof(CK_ULONG)) {
			memcpy(template->pValue, &matrix_row, sizeof(CK_ULONG));
			template->ulValueLen = sizeof(CK_ULONG);
			return (CKR_OK);
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_BUFFER_TOO_SMALL);
		}

		break;
	}
	case CKA_CPK_POINT_COMPRESSED:
	{
		CK_BBOOL compressed = matrix->points->data[0] ? CK_TRUE : CK_FALSE;

		if (template->pValue == NULL) {
			template->ulValueLen = sizeof(CK_BBOOL);
			return (CKR_OK);
		} else if (template->ulValueLen >= sizeof(CK_BBOOL)) {
			memcpy(template->pValue, &compressed, sizeof(CK_BBOOL));
			template->ulValueLen = sizeof(CK_BBOOL);
			return (CKR_OK);
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_BUFFER_TOO_SMALL);
		}

		break;
	}
	default:
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

}


CK_RV
cpk_get_secret_matrix_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	CK_RV rv = CKR_OK;
	CPK_PUBLIC_MATRIX *matrix = object_p->object_u.public_matrix;

	switch (template->type) {
	case CKA_CPK_MATRIX_URI:
	{
		CK_BYTE_PTR matrix_uri = (CK_BYTE_PTR)matrix->matrix_uri->data;
		CK_ULONG matrix_uri_len = (CK_ULONG)matrix->matrix_uri->length;

		if (template->pValue == NULL) {
			template->ulValueLen = matrix_uri_len;
			return (CKR_OK);
		} else if (template->ulValueLen >= matrix_uri_len) {
			memcpy(template->pValue, matrix_uri, matrix_uri_len);
			template->ulValueLen = matrix_uri_len;
			return (CKR_OK);
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_BUFFER_TOO_SMALL);
		}
		break;
	}
	case CKA_CPK_EC_NAME:
	{
		const char *ec_name = OBJ_nid2sn(OBJ_obj2nid(matrix->curve_obj));
		size_t ec_name_len = strlen(ec_name);

		if (template->pValue == NULL) {
			template->ulValueLen = (CK_ULONG)ec_name_len;
			return (CKR_OK);
		} else if (template->ulValueLen >= (CK_ULONG)ec_name_len) {
			memcpy(template->pValue, ec_name, ec_name_len);
			template->ulValueLen = ec_name_len;
			return (CKR_OK);
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_BUFFER_TOO_SMALL);
		}
		break;		
	}
	case CKA_CPK_MATRIX_COLUMN:
	{
		CK_ULONG matrix_column = matrix->column_size;

		if (template->pValue == NULL) {
			template->ulValueLen = sizeof(CK_ULONG);
			return (CKR_OK);
		} else if (template->ulValueLen >= sizeof(CK_ULONG)) {
			memcpy(template->pValue, &matrix_column, sizeof(CK_ULONG));
			template->ulValueLen = sizeof(CK_ULONG);
			return (CKR_OK);
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_BUFFER_TOO_SMALL);
		}
		break;
	}
	case CKA_CPK_MATRIX_ROW:
	{
		CK_ULONG matrix_row = matrix->row_size;

		if (template->pValue == NULL) {
			template->ulValueLen = sizeof(CK_ULONG);
			return (CKR_OK);
		} else if (template->ulValueLen >= sizeof(CK_ULONG)) {
			memcpy(template->pValue, &matrix_row, sizeof(CK_ULONG));
			template->ulValueLen = sizeof(CK_ULONG);
			return (CKR_OK);
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_BUFFER_TOO_SMALL);
		}

		break;
	}
	default:
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	//return (rv);
}

CK_RV
cpk_get_identitiy_info_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	CK_RV rv = CKR_OK;
	CPK_IDENTITY_INFO *identity_info = object_p->object_u.identity_info;

	if (identity_info == NULL_PTR) {
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	switch (template->type) {
	case CKA_CPK_ID:
		rv = get_string_attr_from_object(identity_info->id_data->data,
			identity_info->id_data->length, template);
		break;

	case CKA_CPK_MATRIX_URI:
		rv = get_string_attr_from_object(identity_info->matrix_uri->data,
			identity_info->matrix_uri->length, template);
		break;

	default:
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	return (rv);
}


CK_RV
cpk_get_key_info_attribute(cpk_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	CK_RV rv = CKR_OK;
	CPK_KEY_INFO *key_info = NULL_PTR;
	CPK_PUBLIC_MATRIX *matrix = NULL_PTR; // FIXME: init

	switch (template->type) {
	case CKA_CPK_MATRIX_URI:
	{
		unsigned char *matrix_uri = matrix->matrix_uri->data;
		int matrix_uri_len = matrix->matrix_uri->length;

		rv = get_string_attr_from_object(matrix_uri, matrix_uri_len, template);
		
		break;
	}
	case CKA_CPK_ID:
	{
		unsigned char *id = key_info->identity->id_data->data;
		int id_len = key_info->identity->id_data->length;

		if (template->pValue == NULL) {
			template->ulValueLen = id_len;
			return (CKR_OK);
		} else if (template->ulValueLen >= id_len) {
			memcpy(template->pValue, id, id_len);
			template->ulValueLen = id_len;
			return (CKR_OK);
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_BUFFER_TOO_SMALL);
		}
		break;
	}
	case CKA_CPK_EC_NAME:
	{
		const char *ec_name = OBJ_nid2sn(OBJ_obj2nid(matrix->curve_obj));
		size_t ec_name_len = strlen(ec_name);

		if (template->pValue == NULL) {
			template->ulValueLen = (CK_ULONG)ec_name_len;
			return (CKR_OK);
		} else if (template->ulValueLen >= (CK_ULONG)ec_name_len) {
			memcpy(template->pValue, ec_name, ec_name_len);
			template->ulValueLen = ec_name_len;
			return (CKR_OK);
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_BUFFER_TOO_SMALL);
		}
		break;		
	}
	default:
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	return (rv);
}
