/** 
* @file xt_listen.c
* @brief Raw socket listener to support Single Packet Authentication
*
* @author Bradley Landherr
*
* @date 04/11/2018
*/
#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/wait.h> // DECLARE_WAITQUEUE
#include <linux/filter.h>
#include <linux/uio.h> // iov_iter
#include <linux/version.h>
#include "drawbridge.h"
#include "key.h"

// defined in xt_state.c
extern struct timer_list *reaper;
extern conntrack_state *knock_state;

// For both IPv4 and IPv6 compiled w/
// tcpdump "udp dst port 53" -dd
struct sock_filter code[] = {
    { 0x28, 0, 0, 0x0000000c }, { 0x15, 0, 4, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 }, { 0x15, 0, 11, 0x00000011 },
    { 0x28, 0, 0, 0x00000038 }, { 0x15, 8, 9, 0x00000035 },
    { 0x15, 0, 8, 0x00000800 }, { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 6, 0x00000011 }, { 0x28, 0, 0, 0x00000014 },
    { 0x45, 4, 0, 0x00001fff }, { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x00000010 }, { 0x15, 0, 1, 0x00000035 },
    { 0x6, 0, 0, 0x00040000 },  { 0x6, 0, 0, 0x00000000 },
};

static int ksocket_receive(struct socket *sock, struct sockaddr_in *addr,
                           unsigned char *buf, int len)
{
    struct msghdr msg;
    int size = 0;
    struct kvec iov;

    if (sock->sk == NULL) {
        return 0;
    }

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_flags = MSG_DONTWAIT;
    msg.msg_name = addr;
    msg.msg_namelen = sizeof(struct sockaddr_in);
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    msg.msg_iocb = NULL;
    iov_iter_init(&msg.msg_iter, WRITE, (struct iovec *)&iov, 1, len);
#else
    msg.msg_iov = &iov;
    msg.msg_iovlen = len;
#endif

    // https://github.com/torvalds/linux/commit/2da62906b1e298695e1bb725927041cd59942c98
    // switching to kernel_recvmsg because it's more consistent across versions
    // https://elixir.bootlin.com/linux/v4.6/source/net/socket.c#L741
    size = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);

    return size;
}

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

int listen(void *data)
{
    int ret, recv_len, error, offset, version;

    // Packet headers
    struct ethhdr *eth_h = NULL;
    struct iphdr *ip_h = NULL;
    struct ipv6hdr *ip6_h = NULL;
    //struct tcphdr * tcp_h;
    //struct udphdr * udp_h;
    unsigned char *proto_h = NULL; // either TCP or UDP
    int proto_h_size;
    struct packet *res = NULL;

    // Socket info
    struct socket *sock;
    struct sockaddr_in source;
    struct timespec64 tm;

    // Buffers
    unsigned char *pkt = kmalloc(MAX_PACKET_SIZE, GFP_KERNEL);
    char *src = kmalloc(32 + 1, GFP_KERNEL);
    pkey_signature *sig = NULL;
    void *hash = NULL;

    struct sock_fprog bpf = {
        .len = ARRAY_SIZE(code),
        .filter = code,
    };

    // Initialize wait queue
    DECLARE_WAITQUEUE(recv_wait, current);

    // Init Crypto Verification
    struct crypto_akcipher *tfm;
    akcipher_request *req = init_keys(&tfm, public_key, KEY_LEN);
    reaper = NULL;

    if (!req) {
        kfree(pkt);
        kfree(src);
        return -1;
    }

    //sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    error = sock_create(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL), &sock);

    if (error < 0) {
        DEBUG_PRINT(KERN_INFO "[-] Could not initialize raw socket\n");
        kfree(pkt);
        kfree(src);
        free_keys(tfm, req);
        return -1;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    ret = sock_setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                          KERNEL_SOCKPTR((void *)&bpf), sizeof(bpf));
#else
    ret = sock_setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, (void *)&bpf,
                          sizeof(bpf));
#endif

    if (ret < 0) {
        DEBUG_PRINT(KERN_INFO "[-] Could not attach bpf filter to socket\n");
        sock_release(sock);
        free_keys(tfm, req);
        kfree(pkt);
        kfree(src);
        return -1;
    }

    reaper = init_reaper(STATE_TIMEOUT);

    if (!reaper) {
        DEBUG_PRINT(KERN_INFO "[-] Failed to initialize connection reaper\n");
        sock_release(sock);
        free_keys(tfm, req);
        kfree(pkt);
        kfree(src);
        return -1;
    }

    //DEBUG_PRINT(KERN_INFO "[+] BPF raw socket thread initialized\n");

    while (1) {
        // Add socket to wait queue
        add_wait_queue(&sock->sk->sk_wq->wait, &recv_wait);

        // Socket recv queue empty, set interruptable
        // release CPU and allow scheduler to preempt the thread
        while (skb_queue_empty(&sock->sk->sk_receive_queue)) {
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(2 * HZ);

            // check exit condition
            if (kthread_should_stop()) {
                // Crucial to remove the wait queue before exiting
                set_current_state(TASK_RUNNING);
                remove_wait_queue(&sock->sk->sk_wq->wait, &recv_wait);

                // Cleanup and exit thread
                sock_release(sock);
                free_keys(tfm, req);
                kfree(pkt);
                kfree(src);
                if (reaper) {
                    cleanup_reaper(reaper);
                }
                do_exit(0);
            }
        }

        // Return to running state and remove socket from wait queue
        set_current_state(TASK_RUNNING);
        remove_wait_queue(&sock->sk->sk_wq->wait, &recv_wait);

        memset(pkt, 0, MAX_PACKET_SIZE);
        if ((recv_len = ksocket_receive(sock, &source, pkt, MAX_PACKET_SIZE)) >
            0) {
            if (recv_len < sizeof(struct packet) ||
                recv_len > MAX_PACKET_SIZE) {
                continue;
            }

            // rust parser
            //validate_packet(pkt, MAX_PACKET_SIZE);

            // Check IP version
            eth_h = (struct ethhdr *)pkt;
            proto_h_size = 0;
            if ((eth_h->h_proto & 0xFF) == 0x08 &&
                ((eth_h->h_proto >> 8) & 0xFF) == 0x00) {
                version = 4;
                ip_h = (struct iphdr *)(pkt + sizeof(struct ethhdr));
                proto_h = (unsigned char *)(pkt + sizeof(struct ethhdr) +
                                            sizeof(struct iphdr));
                inet_ntoa(src, ip_h->saddr);
                offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

                // check protocol
                if ((ip_h->protocol & 0xFF) == 0x06) {
                    proto_h_size = (((struct tcphdr *)proto_h)->doff) * 4;

                    // tcp spec
                    if (proto_h_size < 20 || proto_h_size > 60) {
                        continue;
                    }

                    offset += proto_h_size + sizeof(struct packet);
                } else if ((ip_h->protocol & 0xFF) == 0x11) {
                    proto_h_size = sizeof(struct udphdr);
                    offset += sizeof(struct udphdr) + sizeof(struct packet);
                }
            } else if ((eth_h->h_proto & 0xFF) == 0x86 &&
                       ((eth_h->h_proto >> 8) & 0xFF) == 0xDD) {
                version = 6;
                ip6_h = (struct ipv6hdr *)(pkt + sizeof(struct ethhdr));
                proto_h = (unsigned char *)(pkt + sizeof(struct ethhdr) +
                                            sizeof(struct ipv6hdr));
                inet6_ntoa(src, &(ip6_h->saddr));
                offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

                // check protocol
                if ((ip6_h->nexthdr & 0xFF) == 0x06) {
                    proto_h_size = (((struct tcphdr *)proto_h)->doff) * 4;

                    // tcp spec
                    if (proto_h_size < 20 || proto_h_size > 60) {
                        continue;
                    }

                    offset += proto_h_size + sizeof(struct packet);
                } else if ((ip6_h->nexthdr & 0xFF) == 0x11) {
                    proto_h_size = sizeof(struct udphdr);
                    offset += sizeof(struct udphdr) + sizeof(struct packet);
                }
            } else {
                // unsupported protocol
                continue;
            }

            // Process packet
            res = (struct packet *)(pkt + offset - sizeof(struct packet));

            // Parse the packet for a signature
            sig = get_signature(pkt, offset);

            if (!sig) {
                DEBUG_PRINT(KERN_INFO "[-] Signature not found in packet\n");
                continue;
            }

            // Hash timestamp + port to unlock
            hash = gen_digest(proto_h + proto_h_size, sizeof(struct packet));

            if (!hash) {
                free_signature(sig);
                continue;
            }

            // Check that the hash matches
            if (memcmp(sig->digest, hash, sig->digest_size) != 0) {
                DEBUG_PRINT(KERN_INFO "-----> Hash not the same\n");
                free_signature(sig);
                kfree(hash);
                continue;
            }

            // Verify the signature
            if (verify_sig_rsa(req, sig) != 0) {
                free_signature(sig);
                kfree(hash);
                continue;
            }

            // Check timestamp (Currently allows 60 sec skew)
            ktime_get_real_ts64(&tm);
            if (tm.tv_sec > res->timestamp.tv_sec + 60) {
                free_signature(sig);
                kfree(hash);
                continue;
            }

            // Add the IP to the connection linked list
            if (version == 4 && ip_h != NULL) {
                if (!state_lookup(knock_state, 4, ip_h->saddr, NULL,
                                  htons(res->port))) {
                    LOG_PRINT(KERN_INFO
                              "[+] drawbridge: Authentication from:%s\n",
                              src);
                    state_add(knock_state, 4, ip_h->saddr, NULL,
                              htons(res->port));
                }
            } else if (version == 6 && ip6_h != NULL) {
                if (!state_lookup(knock_state, 6, 0, &(ip6_h->saddr),
                                  htons(res->port))) {
                    LOG_PRINT(KERN_INFO
                              "[+] drawbridge: Authentication from:%s\n",
                              src);
                    state_add(knock_state, 6, 0, &(ip6_h->saddr),
                              htons(res->port));
                }
            }

            free_signature(sig);
            kfree(hash);
        }
    }

    sock_release(sock);
    free_keys(tfm, req);
    kfree(pkt);
    kfree(src);
    if (reaper) {
        cleanup_reaper(reaper);
    }
    do_exit(0);
}
