/********************************************************************************/
/*										*/
/*			     TSS Library Dependent Crypto Support		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*		ECC Salt functions written by Bill Martin			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2023.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* Interface to OpenSSL version 1.0.2, 1.1.1, 3.n crypto library */

#include <string.h>
#include <stdio.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <ibmtss/tssresponsecode.h>
#include "tssproperties.h"
#include <ibmtss/tssutils.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssmarshal.h>

#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>

#include <mbedtls/aes.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/rsa.h>

extern int tssVverbose;
extern int tssVerbose;

LIB_EXPORT
TPM_RC TSS_Crypto_Init(void)
{
	return TPM_RC_SUCCESS;
}

LIB_EXPORT
TPM_RC TSS_Hash_Generate_valist(TPMT_HA* digest,
	va_list ap)
{
	TPM_RC rc = 0;
	mbedtls_md_context_t ctx;
	const mbedtls_md_info_t* md_info;
	int done = FALSE;
	uint8_t* buffer;	/* segment to hash */
	int length;		/* segment to hash */

	mbedtls_md_init(&ctx);

	switch (digest->hashAlg) {
#ifdef TPM_ALG_SHA1
	case TPM_ALG_SHA1:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
		break;
#endif
#ifdef TPM_ALG_SHA256
	case TPM_ALG_SHA256:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		break;
#endif
#ifdef TPM_ALG_SHA384
	case TPM_ALG_SHA384:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
		break;
#endif
#ifdef TPM_ALG_SHA512
	case TPM_ALG_SHA512:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
		break;
#endif
	default:
		rc = TSS_RC_BAD_HASH_ALGORITHM;
		goto cleanup;
	}

	if (mbedtls_md_setup(&ctx, md_info, 0) != 0) {
		if (tssVerbose) printf("TSS_Hash_Generate_valist: mbedtls_md_setup failed\n");
		rc = TSS_RC_HASH;
		goto cleanup;
	}

	if (mbedtls_md_starts(&ctx) != 0) {
		if (tssVerbose) printf("TSS_Hash_Generate_valist: mbedtls_md_starts failed\n");
		rc = TSS_RC_HASH;
		goto cleanup;
	}

	while ((rc == 0) && !done) {
		length = va_arg(ap, int);		/* first vararg is the length */
		buffer = va_arg(ap, unsigned char*);	/* second vararg is the array */
		if (buffer != NULL) {			/* loop until a NULL buffer terminates */
			if (length < 0) {
				if (tssVerbose) printf("TSS_Hash_Generate_valist: Length is negative\n");
				rc = TSS_RC_HMAC;
			}
			else {
				if (mbedtls_md_update(&ctx, buffer, length) != 0) {
					if (tssVerbose) printf("TSS_Hash_Generate_valist: mbedtls_md_update failed\n");
					rc = TSS_RC_HASH;
					goto cleanup;
				}

			}
		}
		else {
			done = TRUE;
		}
	}

	if (mbedtls_md_finish(&ctx, digest->digest.tssmax) != 0) {
		if (tssVerbose) printf("TSS_Hash_Generate_valist: mbedtls_md_finish failed\n");
		rc = TSS_RC_HASH;
		goto cleanup;
	}

	rc = TPM_RC_SUCCESS;
	goto cleanup;

cleanup:
	mbedtls_md_free(&ctx);
	return rc;
}

LIB_EXPORT
TPM_RC TSS_HMAC_Generate_valist(TPMT_HA* digest,
	const TPM2B_KEY* hmacKey,
	va_list ap)
{
	TPM_RC rc = 0;
	mbedtls_md_context_t ctx;
	const mbedtls_md_info_t* md_info;
	int done = FALSE;
	uint8_t* buffer;	/* segment to hash */
	int length;		/* segment to hash */

	mbedtls_md_init(&ctx);

	switch (digest->hashAlg) {
#ifdef TPM_ALG_SHA1
	case TPM_ALG_SHA1:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
		break;
#endif
#ifdef TPM_ALG_SHA256
	case TPM_ALG_SHA256:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		break;
#endif
#ifdef TPM_ALG_SHA384
	case TPM_ALG_SHA384:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
		break;
#endif
#ifdef TPM_ALG_SHA512
	case TPM_ALG_SHA512:
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
		break;
#endif
	default:
		rc = TSS_RC_BAD_HASH_ALGORITHM;
		goto cleanup;
	}

	if (mbedtls_md_setup(&ctx, md_info, 1) != 0) {
		if (tssVerbose) printf("TSS_HMAC_Generate_valist: mbedtls_md_setup failed\n");
		rc = TSS_RC_HASH;
		goto cleanup;
	}

	if (mbedtls_md_hmac_starts(&ctx, hmacKey->t.buffer, hmacKey->t.size) != 0) {
		if (tssVerbose) printf("TSS_HMAC_Generate_valist: mbedtls_md_hmac_starts failed\n");
		rc = TSS_RC_HASH;
		goto cleanup;
	}

	while ((rc == 0) && !done) {
		length = va_arg(ap, int);		/* first vararg is the length */
		buffer = va_arg(ap, unsigned char*);	/* second vararg is the array */
		if (buffer != NULL) {			/* loop until a NULL buffer terminates */
			if (length < 0) {
				if (tssVerbose) printf("TSS_HMAC_Generate_valist: Length is negative\n");
				rc = TSS_RC_HMAC;
			}
			else {
				if (mbedtls_md_hmac_update(&ctx, buffer, length) != 0) {
					if (tssVerbose) printf("TSS_HMAC_Generate_valist: mbedtls_md_hmac_update failed\n");
					rc = TSS_RC_HASH;
					goto cleanup;
				}

			}
		}
		else {
			done = TRUE;
		}
	}

	if (mbedtls_md_hmac_finish(&ctx, digest->digest.tssmax) != 0) {
		if (tssVerbose) printf("TSS_HMAC_Generate_valist: mbedtls_md_hmac_finish failed\n");
		rc = TSS_RC_HASH;
		goto cleanup;
	}

	rc = TPM_RC_SUCCESS;
	goto cleanup;

cleanup:
	mbedtls_md_free(&ctx);
	return rc;
}

LIB_EXPORT
TPM_RC TSS_RandBytes(unsigned char* buffer, uint32_t size)
{
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, "ibmtss", 6);

	if (mbedtls_ctr_drbg_random(&ctr_drbg, buffer, size) != 0) {
		if (tssVerbose) printf("TSS_RandBytes: mbedtls_ctr_drbg_random failed\n");
		return TSS_RC_RNG_FAILURE;
	}

	return TPM_RC_SUCCESS;
}

LIB_EXPORT
void TSS_RsaFree(void* rsaKey)
{
	mbedtls_rsa_context* ctx = (mbedtls_rsa_context*)rsaKey;

	mbedtls_rsa_free(ctx);

	free(rsaKey);
}

LIB_EXPORT
TPM_RC TSS_RsaNew(void** rsaKey)
{
	mbedtls_rsa_context* ctx = NULL;

	ctx = malloc(sizeof(mbedtls_rsa_context));
	if (!ctx) {
		return TSS_RC_OUT_OF_MEMORY;
	}

	mbedtls_rsa_init(ctx);

	*rsaKey = (void*)ctx;

	return TPM_RC_SUCCESS;
}

LIB_EXPORT
TPM_RC TSS_RSAGeneratePublicTokenI(void** rsa_pub_key,		/* freed by caller */
	const unsigned char* narr,   	/* public modulus */
	uint32_t nbytes,
	const unsigned char* earr,   	/* public exponent */
	uint32_t ebytes)
{
	TPM_RC rc = 0;
	mbedtls_mpi n = { 0 };
	mbedtls_mpi e = { 0 };
	mbedtls_rsa_context* ctx = NULL;

	mbedtls_mpi_init(&n);
	mbedtls_mpi_init(&e);

	ctx = malloc(sizeof(mbedtls_rsa_context));
	if (!ctx) {
		rc = TSS_RC_OUT_OF_MEMORY;
		goto error;
	}

	mbedtls_rsa_init(ctx);

	if (mbedtls_mpi_read_binary(&n, narr, nbytes) != 0) {
		if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: mbedtls_mpi_read_binary failed\n");
		rc = TSS_RC_RSA_KEY_CONVERT;
		goto error;
	}

	if (mbedtls_mpi_read_binary(&e, earr, ebytes) != 0) {
		if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: mbedtls_mpi_read_binary failed\n");
		rc = TSS_RC_RSA_KEY_CONVERT;
		goto error;
	}

	if (mbedtls_rsa_import(ctx, &n, NULL, NULL, NULL, &e) != 0) {
		if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: mbedtls_rsa_import failed\n");
		rc = TSS_RC_RSA_KEY_CONVERT;
		goto error;
	}

	if (mbedtls_rsa_complete(ctx) != 0) {
		if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: mbedtls_rsa_complete failed\n");
		rc = TSS_RC_RSA_KEY_CONVERT;
		goto error;
	}

	*rsa_pub_key = (void*)ctx;

	rc = TPM_RC_SUCCESS;
	goto cleanup;

error:
	if (ctx) {
		mbedtls_rsa_free(ctx);
		free(ctx);
	}

cleanup:
	mbedtls_mpi_free(&n);
	mbedtls_mpi_free(&e);

	return rc;
}

LIB_EXPORT
TPM_RC TSS_RSAPublicEncrypt(unsigned char* encrypt_data,
	size_t encrypt_data_size,
	const unsigned char* decrypt_data,
	size_t decrypt_data_size,
	unsigned char* narr,
	uint32_t nbytes,
	unsigned char* earr,
	uint32_t ebytes,
	unsigned char* p,
	int pl,
	TPMI_ALG_HASH halg)
{
	TPM_RC rc = 0;
	mbedtls_rsa_context* ctx = NULL;
	mbedtls_entropy_context entropy;
	mbedtls_md_type_t md;

	switch (halg) {
#ifdef TPM_ALG_SHA1
	case TPM_ALG_SHA1:
		md = MBEDTLS_MD_SHA1;
		break;
#endif
#ifdef TPM_ALG_SHA256
	case TPM_ALG_SHA256:
		md = MBEDTLS_MD_SHA256;
		break;
#endif
#ifdef TPM_ALG_SHA384
	case TPM_ALG_SHA384:
		md = MBEDTLS_MD_SHA384;
		break;
#endif
#ifdef TPM_ALG_SHA512
	case TPM_ALG_SHA512:
		md = MBEDTLS_MD_SHA512;
		break;
#endif
	default:
		rc = TSS_RC_BAD_HASH_ALGORITHM;
		goto cleanup;
	}

	mbedtls_entropy_init(&entropy);



	rc = TSS_RSAGeneratePublicTokenI(&ctx, narr, nbytes, earr, ebytes);
	if (rc != TPM_RC_SUCCESS) {
		if (tssVerbose) printf("TSS_RSAPublicEncrypt: TSS_RSAGeneratePublicTokenI failed\n");
		goto error;
	}

	if (mbedtls_rsa_set_padding(ctx, MBEDTLS_RSA_PKCS_V15, md) != 0) {
		if (tssVerbose) printf("TSS_RSAPublicEncrypt: mbedtls_rsa_set_padding failed\n");
		rc = TSS_RC_RSA_PADDING;
		goto error;
	}

	if (mbedtls_rsa_rsaes_oaep_encrypt(ctx, mbedtls_entropy_func, &entropy, p, pl, decrypt_data_size, decrypt_data, encrypt_data) != 0) {
		if (tssVerbose) printf("TSS_RSAPublicEncrypt: mbedtls_rsa_rsaes_oaep_encrypt failed\n");
		rc = TSS_RC_RSA_ENCRYPT;
		goto error;
	}

	rc = TPM_RC_SUCCESS;
	goto cleanup;

error:

cleanup:
	if (ctx) {
		TSS_RsaFree(ctx);
	}
	mbedtls_entropy_free(&entropy);

	return rc;
}

TPM_RC TSS_AES_KeyAllocate(void** tssSessionEncKey,
	void** tssSessionDecKey)
{
	TPM_RC rc = 0;
	mbedtls_aes_context* enc_ctx = NULL;
	mbedtls_aes_context* dec_ctx = NULL;

	enc_ctx = malloc(sizeof(mbedtls_aes_context));
	if (!enc_ctx) {
		rc = TSS_RC_OUT_OF_MEMORY;
		goto error;
	}

	dec_ctx = malloc(sizeof(mbedtls_aes_context));
	if (!dec_ctx) {
		rc = TSS_RC_OUT_OF_MEMORY;
		goto error;
	}

	mbedtls_aes_init(enc_ctx);
	mbedtls_aes_init(dec_ctx);

	*tssSessionEncKey = (void*)enc_ctx;
	*tssSessionDecKey = (void*)dec_ctx;

	rc = TPM_RC_SUCCESS;
	goto cleanup;

error:
	if (dec_ctx) {
		mbedtls_aes_free(dec_ctx);
		free(dec_ctx);
	}
	if (enc_ctx) {
		mbedtls_aes_free(enc_ctx);
		free(enc_ctx);
	}

cleanup:
	return rc;
}

TPM_RC TSS_AES_KeyFree(void* tssSessionEncKey,
	void* tssSessionDecKey)
{
	mbedtls_aes_context* enc_ctx = (mbedtls_aes_context*)tssSessionEncKey;
	mbedtls_aes_context* dec_ctx = (mbedtls_aes_context*)tssSessionDecKey;

	if (dec_ctx) {
		mbedtls_aes_free(dec_ctx);
		free(dec_ctx);
	}
	if (enc_ctx) {
		mbedtls_aes_free(enc_ctx);
		free(enc_ctx);
	}

	return TPM_RC_SUCCESS;
}

#define TSS_AES_KEY_BITS 128

TPM_RC TSS_AES_KeyGenerate(void* tssSessionEncKey,
	void* tssSessionDecKey)
{
	TPM_RC		rc = 0;
	unsigned char 	userKey[AES_128_BLOCK_SIZE_BYTES];
	const char* envKeyString = NULL;
	unsigned char* envKeyBin = NULL;
	size_t 		envKeyBinLen;
	mbedtls_aes_context* enc_ctx = (mbedtls_aes_context*)tssSessionEncKey;
	mbedtls_aes_context* dec_ctx = (mbedtls_aes_context*)tssSessionDecKey;

	if (rc == 0) {
		envKeyString = getenv("TPM_SESSION_ENCKEY");
	}
	if (envKeyString == NULL) {
		/* If the env variable TPM_SESSION_ENCKEY is not set, generate a random key for this
		   TSS_CONTEXT */
		if (rc == 0) {
			/* initialize userKey to silence valgrind false positive */
			memset(userKey, 0, sizeof(userKey));
			rc = TSS_RandBytes(userKey, AES_128_BLOCK_SIZE_BYTES);
		}
	}
	/* The env variable TPM_SESSION_ENCKEY can set a (typically constant) encryption key.  This is
	   useful for scripting, where the env variable is set to a random seed at the beginning of the
	   script. */
	else {
		/* hexascii to binary */
		if (rc == 0) {
			rc = TSS_Array_Scan(&envKeyBin,			/* freed @1 */
				&envKeyBinLen, envKeyString);
		}
		/* range check */
		if (rc == 0) {
			if (envKeyBinLen != AES_128_BLOCK_SIZE_BYTES) {
				if (tssVerbose)
					printf("TSS_AES_KeyGenerate: Error, env variable length %lu not %lu\n",
						(unsigned long)envKeyBinLen, (unsigned long)sizeof(userKey));
				rc = TSS_RC_BAD_PROPERTY_VALUE;
			}
		}
		/* copy the binary to the common userKey for use below */
		if (rc == 0) {
			memcpy(userKey, envKeyBin, envKeyBinLen);
		}
	}

	if (mbedtls_aes_setkey_enc(enc_ctx, userKey, TSS_AES_KEY_BITS) != 0) {
		if (tssVerbose) printf("TSS_AES_KeyGenerate: mbedtls_aes_setkey_enc failed\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
		goto error;
	}

	if (mbedtls_aes_setkey_dec(dec_ctx, userKey, TSS_AES_KEY_BITS) != 0) {
		if (tssVerbose) printf("TSS_AES_KeyGenerate: mbedtls_aes_setkey_dec failed\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
		goto error;
	}

	rc = TPM_RC_SUCCESS;
	goto cleanup;

error:
cleanup:
	if (envKeyBin) free(envKeyBin);
	return rc;
}

TPM_RC TSS_AES_Encrypt(void* tssSessionEncKey,
	unsigned char** encrypt_data,
	uint32_t* encrypt_length,
	const unsigned char* decrypt_data,
	uint32_t decrypt_length)
{
	TPM_RC		rc = 0;
	mbedtls_aes_context* enc_ctx = (mbedtls_aes_context*)tssSessionEncKey;
	uint32_t		pad_length;
	unsigned char* decrypt_data_pad = NULL;
	unsigned char	ivec[AES_128_BLOCK_SIZE_BYTES];       /* initial chaining vector */

	if (rc == 0) {
		/* calculate the pad length and padded data length */
		pad_length = AES_128_BLOCK_SIZE_BYTES - (decrypt_length % AES_128_BLOCK_SIZE_BYTES);
		*encrypt_length = decrypt_length + pad_length;
		/* allocate memory for the encrypted response */
		rc = TSS_Malloc(encrypt_data, *encrypt_length);
	}
	/* allocate memory for the padded decrypted data */
	if (rc == 0) {
		rc = TSS_Malloc(&decrypt_data_pad, *encrypt_length);    /* freed @1 */
	}
	/* pad the decrypted clear text data */
	if (rc == 0) {
		/* unpadded original data */
		memcpy(decrypt_data_pad, decrypt_data, decrypt_length);
		/* last gets pad = pad length */
		memset(decrypt_data_pad + decrypt_length, pad_length, pad_length);
	}

	memset(ivec, 0, sizeof(ivec));

	if (mbedtls_aes_crypt_cbc(enc_ctx, MBEDTLS_AES_ENCRYPT, *encrypt_length, ivec, decrypt_data_pad, *encrypt_data) != 0) {
		if (tssVerbose) printf("TSS_AES_Encrypt: mbedtls_aes_crypt_cbc failed\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
		goto error;
	}

	rc = TPM_RC_SUCCESS;
	goto cleanup;

error:
cleanup:
	if (decrypt_data_pad) free(decrypt_data_pad);
	return rc;
}


TPM_RC TSS_AES_Decrypt(void* tssSessionDecKey,
	unsigned char** decrypt_data,
	uint32_t* decrypt_length,
	const unsigned char* encrypt_data,
	uint32_t encrypt_length)
{
	TPM_RC		rc = 0;
	mbedtls_aes_context* dec_ctx = (mbedtls_aes_context*)tssSessionDecKey;
	uint32_t		pad_length;
	uint32_t		i;
	unsigned char* pad_data;
	unsigned char	ivec[AES_128_BLOCK_SIZE_BYTES];       /* initial chaining vector */

	/* sanity check encrypted length */
	if (rc == 0) {
		if (encrypt_length < AES_128_BLOCK_SIZE_BYTES) {
			if (tssVerbose) printf("TSS_AES_Decrypt: Error, bad length %u\n",
				encrypt_length);
			rc = TSS_RC_AES_DECRYPT_FAILURE;
		}
	}
	/* allocate memory for the padded decrypted data */
	if (rc == 0) {
		rc = TSS_Malloc(decrypt_data, encrypt_length);
	}

	memset(ivec, 0, sizeof(ivec));

	if (mbedtls_aes_crypt_cbc(dec_ctx, MBEDTLS_AES_DECRYPT, encrypt_length, ivec, encrypt_data, *decrypt_data) != 0) {
		if (tssVerbose) printf("TSS_AES_Encrypt: mbedtls_aes_crypt_cbc failed\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
		goto error;
	}
	/* get the pad length */
	if (rc == 0) {
		/* get the pad length from the last byte */
		pad_length = (uint32_t) * (*decrypt_data + encrypt_length - 1);
		/* sanity check the pad length */
		if ((pad_length == 0) ||
			(pad_length > AES_128_BLOCK_SIZE_BYTES)) {
			if (tssVerbose) printf("TSS_AES_Decrypt: Error, illegal pad length\n");
			rc = TSS_RC_AES_DECRYPT_FAILURE;
		}
	}
	if (rc == 0) {
		/* get the unpadded length */
		*decrypt_length = encrypt_length - pad_length;
		/* pad starting point */
		pad_data = *decrypt_data + *decrypt_length;
		/* sanity check the pad */
		for (i = 0; (rc == 0) && (i < pad_length); i++, pad_data++) {
			if (*pad_data != pad_length) {
				if (tssVerbose) printf("TSS_AES_Decrypt: Error, bad pad %02x at index %u\n",
					*pad_data, i);
				rc = TSS_RC_AES_DECRYPT_FAILURE;
			}
		}
	}

	rc = TPM_RC_SUCCESS;
	goto cleanup;

error:
	if (*decrypt_data) {
		free(*decrypt_data);
		*decrypt_data = NULL;
	}
cleanup:
	return rc;
}

TPM_RC TSS_AES_EncryptCFB(uint8_t* dOut,
	uint32_t	keySizeInBits,
	uint8_t* key,
	uint8_t* iv,
	uint32_t	dInSize,
	uint8_t* dIn)
{
	TPM_RC	rc = 0;
	mbedtls_aes_context aes_ctx;
	size_t iv_off = 0;

	mbedtls_aes_init(&aes_ctx);

	if (mbedtls_aes_setkey_enc(&aes_ctx, key, keySizeInBits) != 0) {
		if (tssVerbose) printf("TSS_AES_EncryptCFB: mbedtls_aes_setkey_enc failed\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
		goto error;
	}

	if (mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_ENCRYPT, dInSize, &iv_off, iv, dIn, dOut) != 0) {
		if (tssVerbose) printf("TSS_AES_EncryptCFB: mmbedtls_aes_crypt_cfb128 failed\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
		goto error;
	}

	rc = TPM_RC_SUCCESS;
	goto cleanup;

error:
cleanup:
	mbedtls_aes_free(&aes_ctx);
	return rc;
}

TPM_RC TSS_AES_DecryptCFB(uint8_t* dOut,
	uint32_t keySizeInBits,
	uint8_t* key,
	uint8_t* iv,
	uint32_t dInSize,
	uint8_t* dIn)
{
	TPM_RC	rc = 0;
	mbedtls_aes_context aes_ctx;
	size_t iv_off = 0;

	mbedtls_aes_init(&aes_ctx);

	if (mbedtls_aes_setkey_enc(&aes_ctx, key, keySizeInBits) != 0) {
		if (tssVerbose) printf("TSS_AES_DecryptCFB: mbedtls_aes_setkey_dec failed\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
		goto error;
	}

	if (mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_DECRYPT, dInSize, &iv_off, iv, dIn, dOut) != 0) {
		if (tssVerbose) printf("TSS_AES_DecryptCFB: mmbedtls_aes_crypt_cfb128 failed\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
		goto error;
	}

	rc = TPM_RC_SUCCESS;
	goto cleanup;

error:
cleanup:
	mbedtls_aes_free(&aes_ctx);
	return rc;
}
