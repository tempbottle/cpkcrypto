/* Copyright (c) 2007  "Guan Zhi" <guanzhi1980@gmail.com> */

#include <openssl/evp.h>
#include "cpk.h"

// FIXME: need a stronger one! the function name should also be changed
int str2index(const EVP_MD *md, int col, int row,
	const char *str, int len, int index[]) 
{
	int r = 0, i;
	
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	BIGNUM *bn = BN_new();
	
	if (!bn) 
		goto err;

	r = EVP_Digest(str, len, dgst, &dgstlen, md, NULL);
	if (!r)
		goto err;
	if (!BN_bin2bn(dgst, dgstlen, bn))
		goto err;
	for (i = 0; i < col; i++) {
		int r = BN_div_word(bn, row);
		index[col-i-1] = r + row * (col-i-1);
	}

	r = 1;
err:
	if (bn) BN_free(bn);
	return r; 
}

