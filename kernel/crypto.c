/*
	Project: Trigger
	Description: Assymetric crypto wrapper API for Single Packet Authentication
	Auther: Bradley Landherr
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include "xt_knock.h"


akcipher_request * init_keys(crypto_akcipher **tfm) {

	// Request struct
	akcipher_request *req;

	*tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);

	if(IS_ERR(tfm)) {
		printk(KERN_INFO	"[!] Could not allocate akcipher handle\n");
		return NULL;
	}

	req = akcipher_request_alloc(*tfm, GFP_KERNEL);

	if(!req) {
		printk(KERN_INFO	"[!] Could not allocate akcipher_request struct\n");
		return NULL;
	}

	return req;
}


void free_keys(crypto_akcipher *tfm, akcipher_request * req) {
	akcipher_request_free(req);
	crypto_free_akcipher(tfm);
}


// Verify a recieved signature
int verify_sig_rsa(akcipher_request * req, crypto_akcipher *tfm, void * signature, int len) {

	struct scatterlist src;

	// Put the data into our request structure
	sg_init_one(&src, signature, len);
	akcipher_request_set_crypt(req, &src, &src, len, crypto_akcipher_maxsize(tfm));

	// Get the result
	return crypto_akcipher_verify(req);
}