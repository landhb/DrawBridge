#include "drawbridge.h"

ssize_t validate_packet(akcipher_request *req, void * pkt, parsed_packet * info, size_t maxsize) {
    struct timespec64 tm;
    //pkey_signature *sig = NULL;
    void *hash = NULL;
    struct packet *metadata = NULL;

    // Process packet
    metadata = (struct packet *)(pkt + info->offset);

    // Parse the packet for a signature, occurs after the timestamp + port
    //sig = parse_signature(pkt, info->offset + sizeof(struct packet));

    if (!info || !info->sig) {
        DEBUG_PRINT(KERN_INFO "[-] Signature not found in packet\n");
        return -1;
    }

    // Hash timestamp + port to unlock
    hash = gen_digest(metadata, sizeof(struct packet));

    if (!hash) {
        //free_signature(sig);
        return -1;
    }

    // Check that the hash matches
    if (memcmp(info->sig->digest, hash, info->sig->digest_size) != 0) {
        DEBUG_PRINT(KERN_INFO "-----> Hash not the same\n");
        //free_signature(sig);
        kfree(hash);
        return -1;
    }

    // Verify the signature
    if (verify_sig_rsa(req, info->sig) != 0) {
        //free_signature(sig);
        kfree(hash);
        return -1;
    }

    // Check timestamp (Currently allows 60 sec skew)
    ktime_get_real_ts64(&tm);
    if (tm.tv_sec > metadata->timestamp.tv_sec + 60) {
        //free_signature(sig);
        kfree(hash);
        return -1;
    }

    // Set the port to unlock
    info->port = metadata->port;

    //free_signature(sig);
    kfree(hash);
    return 0;
}