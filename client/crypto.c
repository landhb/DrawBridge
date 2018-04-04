#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/types.h>

// From https://www.bmt-online.org/geekisms/RSA_verify
int sign_data(
		const void *buf,    /* input data: byte array */
		size_t buf_len, 
		RSA *pkey,         /* input private key: byte array of the PEM representation */
		void **out_sig,     /* output signature block, allocated in the function */
		unsigned int *out_sig_len,
		void **out_digest,
		unsigned int *out_digest_len) {

	int status = EXIT_SUCCESS;
	int rc = 1;
	BIO *b = NULL;
	RSA *r = NULL;
	unsigned char *sig = NULL;
	unsigned int sig_len = 0;

	SHA_CTX sha_ctx = { 0 };
	unsigned char * digest = malloc(SHA_DIGEST_LENGTH);

	rc = SHA1_Init(&sha_ctx);

	if (1 != rc) { 
		status = EXIT_FAILURE; 
		goto end; 
	}

	rc = SHA1_Update(&sha_ctx, buf, buf_len);

	if (1 != rc) { 
		status = EXIT_FAILURE; 
		goto end; 
	}

	rc = SHA1_Final(digest, &sha_ctx);

	if (1 != rc) { 
		status = EXIT_FAILURE; 
		goto end; 
	}

	//b = BIO_new_mem_buf(pkey, pkey_len);
	//r = PEM_read_bio_RSAPrivateKey(b, NULL, NULL, NULL);
	r = pkey;

	sig = malloc(RSA_size(r));

	if (NULL == sig) { 
		status = EXIT_FAILURE; 
		goto end; 
	}

	rc = RSA_sign(NID_sha1, digest, sizeof digest, sig, &sig_len, r);

	if (1 != rc) { 
		status = EXIT_FAILURE; 
		goto end; 
	}

	*out_sig = sig;
	*out_sig_len = sig_len;
	*out_digest = digest;
	*out_digest_len = SHA_DIGEST_LENGTH;
end:
	if (NULL != r) RSA_free(r);
	if (NULL != b) BIO_free(b);
	if (EXIT_SUCCESS != status) free(sig); /* in case of failure: free allocated resource */
	if (1 != rc) fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return status;
}