/*
	Project: Trigger
	Description: Assymetric crypto wrapper API for Single Packet Authentication
	Auther: Bradley Landherr
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <crypto/internal/rsa.h>
#include <crypto/internal/akcipher.h>
#include <linux/version.h>
#include "trigger.h"

// Stores the result of an async operation
typedef struct op_result {
	struct completion completion;
	int err;
} op_result;


static const u8 RSA_digest_info_SHA1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x0E, 0x03, 0x02, 0x1A,
	0x05, 0x00, 0x04, 0x14
};

static const u8 RSA_digest_info_SHA256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x20
};

typedef struct RSA_ASN1_template {
	const u8 * data;
	size_t size;
} RSA_ASN1_template;

RSA_ASN1_template sha1_template;
RSA_ASN1_template sha256_template;


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
	struct crypto_ahash *tfm;
	struct ahash_request *req;
	unsigned char * output = NULL;
	int MAX_OUT; 


	tfm = crypto_alloc_ahash("sha1", 0 , CRYPTO_ALG_ASYNC);

	if(IS_ERR(tfm)) {
		return NULL;
	}

	sg_init_one(&src, buf, len);

	req = ahash_request_alloc(tfm, GFP_ATOMIC);

	if(IS_ERR(req)) {
		crypto_free_ahash(tfm);
		return NULL;
	}

	MAX_OUT = crypto_ahash_digestsize(tfm);
	output = kzalloc(MAX_OUT, GFP_KERNEL);

	if(!output) {
		crypto_free_ahash(tfm);
		ahash_request_free(req);
		return NULL;
	}

	ahash_request_set_callback(req, 0, NULL, NULL);
	ahash_request_set_crypt(req, &src, output, len);

	if (crypto_ahash_digest(req)) {
		crypto_free_ahash(tfm);
		ahash_request_free(req);
		kfree(output);
		return NULL;
	}


	crypto_free_ahash(tfm);
	ahash_request_free(req);

	return output;
}

// Derived from https://github.com/torvalds/linux/blob/db6c43bd2132dc2dd63d73a6d1ed601cffd0ae06/crypto/asymmetric_keys/rsa.c#L101
// and https://tools.ietf.org/html/rfc8017#section-9.2
// thanks to Maarten Bodewes for answering the question on Stackoverflow
// https://stackoverflow.com/questions/49662595/linux-kernel-rsa-signature-verification-crypto-akcipher-verify-output
static char *pkcs_1_v1_5_decode_emsa(unsigned char * EM,
						unsigned long  EMlen,
						const u8 * asn1_template,
						size_t asn1_size,
						size_t hash_size)
{
	unsigned int t_offset, ps_end, ps_start, i;

	if (EMlen < 2 + 1 + asn1_size + hash_size)
		return NULL;	

	/* Decode the EMSA-PKCS1-v1_5
	 * note: leading zeros are stripped by the RSA implementation in older kernels
	 * so   EM = 0x00 || 0x01 || PS || 0x00 || T
	 * will become EM = 0x01 || PS || 0x00 || T.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
	ps_start = 1;
	if (EM[0] != 0x01) {
		printk(" = -EBADMSG [EM[0] == %02u]", EM[0]);
		return NULL;
	}
#else
	ps_start = 2;
	if (EM[0] != 0x00 || EM[1] != 0x01) {
		printk(" = -EBADMSG [EM[0] == %02u] [EM[1] == %02u]", EM[0], EM[1]);
		return NULL;
	}
#endif

	// Calculate offsets
	t_offset = EMlen - (asn1_size + hash_size);
	ps_end = t_offset - 1;

	// Check if there's a 0x00 seperator between PS and T
	if (EM[ps_end] != 0x00) {
		printk(" = -EBADMSG [EM[T-1] == %02u]", EM[ps_end]);
		return NULL;
	}

	// Check the PS 0xff padding 
	for (i = ps_start; i < ps_end; i++) {
		if (EM[i] != 0xff) {
			printk(" = -EBADMSG [EM[PS%x] == %02u]", i - 2, EM[i]);
			return NULL;
		}
	}

	return EM + t_offset + asn1_size;
	
}


// Verify a recieved signature
int verify_sig_rsa(akcipher_request * req, pkey_signature * sig) {

	int err;
	void *inbuf, *outbuf, *result = NULL;
	op_result res;
	struct scatterlist src, dst;
	crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	int MAX_OUT = crypto_akcipher_maxsize(tfm);


	inbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);

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

	// Decode the PKCS#1 v1.5 encoding
	sha1_template.data = RSA_digest_info_SHA1;
	sha1_template.size = ARRAY_SIZE(RSA_digest_info_SHA1);
	result = pkcs_1_v1_5_decode_emsa(outbuf, req->dst_len, sha1_template.data, sha1_template.size, 20);

	err = -EINVAL;
	if(!result) {
		printk(KERN_INFO "[!] EMSA PKCS#1 v1.5 decode failed\n");
		kfree(inbuf);
		kfree(outbuf);
		return err;
	}

	printk(KERN_INFO "\nComputation:\n");
	hexdump(result, 20); 

	/* Do the actual verification step. */
	if (memcmp(sig->digest, outbuf + MAX_OUT - sig->digest_size - 1, sig->digest_size) != 0) {
		printk(KERN_INFO "[!] Signature verification failed - Key Rejected: %d\n", -EKEYREJECTED);
		kfree(inbuf);
		kfree(outbuf);
		return -EKEYREJECTED;
	}
		
	printk(KERN_INFO "[+] RSA signature verification passed\n");
	kfree(inbuf);
	kfree(outbuf);
	return 0;
}