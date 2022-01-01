#include "drawbridge.h"

static void free_signature(pkey_signature *sig)
{
    if (sig->s) {
        kfree(sig->s);
    }
    if (sig->digest) {
        kfree(sig->digest);
    }
    kfree(sig);
}

// Pointer arithmatic to parse out the signature and digest
static pkey_signature *get_signature(void *pkt, u32 offset)
{
    // Allocate the result struct
    pkey_signature *sig = kzalloc(sizeof(pkey_signature), GFP_KERNEL);

    if (sig == NULL) {
        return NULL;
    }

    // Get the signature size
    sig->s_size = *(u32 *)(pkt + offset);

    // Sanity check the sig size
    if (sig->s_size > MAX_SIG_SIZE ||
        (offset + sig->s_size + sizeof(u32) > MAX_PACKET_SIZE)) {
        kfree(sig);
        return NULL;
    }

    // Copy the signature from the packet
    sig->s = kzalloc(sig->s_size, GFP_KERNEL);

    if (sig == NULL) {
        return NULL;
    }

    // copy the signature
    offset += sizeof(u32);
    memcpy(sig->s, pkt + offset, sig->s_size);

    // Get the digest size
    offset += sig->s_size;
    sig->digest_size = *(u32 *)(pkt + offset);

    // Sanity check the digest size
    if (sig->digest_size > MAX_DIGEST_SIZE ||
        (offset + sig->digest_size + sizeof(u32) > MAX_PACKET_SIZE)) {
        kfree(sig->s);
        kfree(sig);
        return NULL;
    }

    // Copy the digest from the packet
    sig->digest = kzalloc(sig->digest_size, GFP_KERNEL);
    offset += sizeof(u32);
    memcpy(sig->digest, pkt + offset, sig->digest_size);

    return sig;
}

ssize_t validate_packet(akcipher_request *req, void * pkt, parsed_packet * info, size_t maxsize) {
    struct timespec64 tm;
    pkey_signature *sig = NULL;
    void *hash = NULL;
    struct packet *metadata = NULL;

    // Process packet
    metadata = (struct packet *)(pkt + info->offset);

    // Parse the packet for a signature, occurs after the timestamp + port
    sig = get_signature(pkt, info->offset + sizeof(struct packet));

    if (!sig) {
        DEBUG_PRINT(KERN_INFO "[-] Signature not found in packet\n");
        return -1;
    }

    // Hash timestamp + port to unlock
    hash = gen_digest(metadata, sizeof(struct packet));

    if (!hash) {
        free_signature(sig);
        return -1;
    }

    // Check that the hash matches
    if (memcmp(sig->digest, hash, sig->digest_size) != 0) {
        DEBUG_PRINT(KERN_INFO "-----> Hash not the same\n");
        free_signature(sig);
        kfree(hash);
        return -1;
    }

    // Verify the signature
    if (verify_sig_rsa(req, sig) != 0) {
        free_signature(sig);
        kfree(hash);
        return -1;
    }

    // Check timestamp (Currently allows 60 sec skew)
    ktime_get_real_ts64(&tm);
    if (tm.tv_sec > metadata->timestamp.tv_sec + 60) {
        free_signature(sig);
        kfree(hash);
        return -1;
    }

    // Set the port to unlock
    info->port = metadata->port;

    free_signature(sig);
    kfree(hash);
    return 0;
}