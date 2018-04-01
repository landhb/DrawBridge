/*
	Project: Trigger
	Description: Assymetric crypto wrapper API for Single Packet Authentication
	Auther: Bradley Landherr
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include "xt_knock.h"

// Stores the result of an async operation
typedef struct op_result {
	struct completion completion;
	int err;
} op_result;





akcipher_request * init_keys(crypto_akcipher **tfm, void * data, int len) {

	// Request struct
	int err;
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

	err = crypto_akcipher_set_pub_key(*tfm, data, len);

	if(err) {
		printk(KERN_INFO	"[!] Could not set the public key\n");
		akcipher_request_free(req);
		return NULL;
	}

	return req;
}


void free_keys(crypto_akcipher *tfm, akcipher_request * req) {
	if(req){
		akcipher_request_free(req);
	}
	if(tfm) {
		crypto_free_akcipher(tfm);
	}
}

// Callback for crypto_async_request completion routine
static void op_complete(struct crypto_async_request *req, int err) {
	op_result *res = (op_result *)(req->data);

	if (err == -EINPROGRESS) {
		return;
	}
	printk(KERN_INFO "Completion code: %d\n", err);
	res->err = err;
	complete(&res->completion);
}


// Wait on crypto operation
static int wait_async_op(op_result * res, int ret) {
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		printk(KERN_INFO "Waiting...%d\n", ret);
		wait_for_completion(&(res->completion));
		reinit_completion(&(res->completion));
		ret = res->err;
	}
	return ret;
}


static inline  void hexdump(unsigned char *buf,unsigned int len) {
	while(len--)
		printk("%02x",*buf++);
	printk("\n");
}

// Verify a recieved signature
int verify_sig_rsa(akcipher_request * req, pkey_signature * sig) {

	int err;
	void *inbuf, *outbuf;
	op_result res;
	struct scatterlist src, dst;
	crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	int MAX_OUT = crypto_akcipher_maxsize(tfm);


	inbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	err = -ENOMEM;
	if(!inbuf) {
		return err;
	}

	outbuf = kzalloc(MAX_OUT, GFP_KERNEL);

	if(!outbuf) {
		kfree(inbuf);
		return err;
	} 

	// Init completion
	init_completion(&(res.completion));

	// Put the data into our request structure
	memcpy(inbuf, sig->s, sig->s_size);
	sg_init_one(&src, inbuf, sig->s_size);
	sg_init_one(&dst, outbuf, MAX_OUT);
	akcipher_request_set_crypt(req, &src, &dst, sig->s_size, MAX_OUT);

	// Set the completion routine callback
	// results from the verify routine will be stored in &res
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, op_complete, &res);

	// Compute the expected digest
	err = wait_async_op(&res, crypto_akcipher_verify(req));

	if(err) {
		printk(KERN_INFO "[!] Digest computation failed %d\n", err);
		kfree(inbuf);
		kfree(outbuf);
		return err;
	}

	/* Do the actual verification step. */
	if (req->dst_len != sig->digest_size ||
		memcmp(sig->digest, outbuf, sig->digest_size) != 0) {
		printk(KERN_INFO "[!] Signature verification failed %d\n", -EKEYREJECTED);
		kfree(inbuf);
		kfree(outbuf);
		return -EKEYREJECTED;
	}
		
	printk(KERN_INFO "[+] RSA signature verification passed %d\n", err);
	kfree(inbuf);
	kfree(outbuf);
	return 0;
}