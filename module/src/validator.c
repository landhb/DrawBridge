/** 
* @file validator.c
* @brief Validates that an SPA packet has been properly signed
*
* @author Bradley Landherr
*
* @date 04/11/2018
*/
#include "drawbridge.h"

ssize_t validate_packet(parsed_packet * info, akcipher_request *req, void * pkt, size_t maxsize) {
    struct timespec64 tm;
    void *hash = NULL;

    if (!info) {
        DEBUG_PRINT(KERN_INFO "[-] Signature not found in packet\n");
        return -1;
    }

    // Hash timestamp + port to unlock
    hash = gen_digest(&info->metadata, sizeof(struct dbpacket));

    if (!hash) {
        return -1;
    }

    // Check that the hash matches
    if (memcmp(info->sig.digest, hash, info->sig.digest_size) != 0) {
        DEBUG_PRINT(KERN_INFO "-----> Hash not the same\n");
        kfree(hash);
        return -1;
    }

    // Verify the signature
    if (verify_sig_rsa(req, &info->sig) != 0) {
        DEBUG_PRINT(KERN_INFO "-----> Signature verification failed\n");
        kfree(hash);
        return -1;
    }

    // Convert metadata to host endianess for any further processing
    info->metadata.timestamp = be64_to_cpu(info->metadata.timestamp);
    info->metadata.port = be16_to_cpu(info->metadata.port);

    // Check timestamp (Currently allows 60 sec skew)
    ktime_get_real_ts64(&tm);
    if (tm.tv_sec > info->metadata.timestamp + 60) {
        kfree(hash);
        return -1;
    }

    // Set the port to unlock
    info->port = info->metadata.port;
    kfree(hash);
    return 0;
}