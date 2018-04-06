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

	*tfm = crypto_alloc_akcipher("rsa", 0, 0);

	if(IS_ERR(*tfm)) {
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
	res->err = err;
	complete(&res->completion);
}


// Wait on crypto operation
static int wait_async_op(op_result * res, int ret) {
	if (ret == -EINPROGRESS || ret == -EBUSY) {
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

void * gen_digest(void * buf, unsigned int len) {
	struct scatterlist src;
	struct hash_desc desc;
	unsigned char * output;
	int MAX_OUT; 

	sg_init_one(&src, buf, len);
	desc.tfm = crypto_alloc_hash("sha1", 0 , CRYPTO_ALG_ASYNC);
	desc.flags = 0;
	MAX_OUT = crypto_hash_digestsize(desc.tfm);
	output = kzalloc(MAX_OUT, GFP_KERNEL);

	crypto_hash_init(&desc);
	crypto_hash_update(&desc, &src, len);
	crypto_hash_final(&desc, output);

	crypto_free_hash(desc.tfm);

	return output;
}


// Verify a recieved signature
int verify_sig_rsa(akcipher_request * req, pkey_signature * sig) {

	int err;
	void *inbuf, *outbuf, *result;
	op_result res;
	struct scatterlist src, dst;
	struct scatterlist * sgl;
	crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	int MAX_OUT = crypto_akcipher_maxsize(tfm);

	inbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);

	err = -ENOMEM;
	if(!inbuf) {
		return err;
	}

	outbuf = kzalloc(MAX_OUT, GFP_KERNEL);
	result = kzalloc(MAX_OUT, GFP_KERNEL);

	if(!outbuf || !result) {
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
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP, op_complete, &res);

	// Compute the expected digest
	err = wait_async_op(&res, crypto_akcipher_verify(req));

	if(err) {
		printk(KERN_INFO "[!] Digest computation failed %d\n", err);
		kfree(inbuf);
		kfree(outbuf);
		kfree(result);
		return err;
	}

	printk(KERN_INFO "\nComputation:\n");
	hexdump(outbuf, req->dst_len);
	printk("%d\n", MAX_OUT);

	printk(KERN_INFO "\nResult:\n");

	// iterate over the scatterlist to get the result
	sgl = &dst;
	while(1) {
		
		if (!sgl)
			break;

		sg_copy_to_buffer(sgl, 1, result, sgl->length);
		hexdump(result, sgl->length);

		sgl = sg_next(sgl);
	}


	/* Do the actual verification step. */
	if (req->dst_len != sig->digest_size ||
		memcmp(sig->digest, outbuf, sig->digest_size) != 0) {
		printk(KERN_INFO "[!] Signature verification failed - Key Rejected: %d\n", -EKEYREJECTED);
		printk(KERN_INFO "[!] Sig len: %d   Computed len: %d\n", sig->digest_size, req->dst_len);
		kfree(inbuf);
		kfree(outbuf);
		kfree(result);
		return -EKEYREJECTED;
	}
		
	printk(KERN_INFO "[+] RSA signature verification passed %d\n", err);
	kfree(inbuf);
	kfree(outbuf);
	return 0;
}