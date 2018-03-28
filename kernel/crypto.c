#include <linux/module.h>
#include <linux/kernel.h>
#include <crypto/akcipher.h>
/*
	Project: Trigger
	Description: Assymetric crypto wrapper API for Single Packet Authentication
	Auther: Bradley Landherr
*/

#include "xt_knock.h"


struct akcipher_request * init_keys(struct crypto_akcipher **tfm) {

	// Request struct
	struct akcipher_request *req;

	tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);

	if(IS_ERR(tfm)) {
		printk(KERN_INFO	"[!] Could not allocate akcipher handle\n");
		return PTR_ERR(tfm);
	}

	req = akcipher_request_alloc(tfm, GFP_KERNEL);

	if(!req) {
		printk(KERN_INFO	"[!] Could not allocate akcipher_request struct\n");
		return NULL;
	}



}


void free_keys(struct crypto_akcipher *tfm, struct akcipher_request * req) {
	akcipher_request_free(req);
	crypto_free_akcipher(tfm);
}


// Verify a recieved signature
int verify_sig_rsa(struct akcipher_request * req, void * signature, int len) {

	struct scatterlist src;

	// Put the data into our request structure
	sg_init_one(&src, signature, len);
	akcipher_request_set_crypt(req, &src, &src, len, crypto_akcipher_maxsize(tfm));

	// Get the result
	return crypto_akcipher_verify(req);
}