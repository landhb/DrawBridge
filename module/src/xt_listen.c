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
#include <linux/wait.h>
#include <linux/filter.h>
#include <linux/uio.h>
#include <linux/version.h>
#include "drawbridge.h"
#include "key.h"
#include "parser.h"

// defined in xt_state.c
extern struct timer_list *reaper;
extern conntrack_state *knock_state;

// defined in xt_hook.c
extern struct completion thread_setup;
extern struct completion thread_done;

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

struct sock_fprog bpf = {
    .len = ARRAY_SIZE(code),
    .filter = code,
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

/**
 *  @brief Listener Thread Entrypoint
 *
 *  Has two completions that must be set to synchronize with the
 *  main thread on module load + unload.
 *
 *  thread_setup completion - Upon initialization success/failure
 *  thread_done completion - Upon thread exit
 *
 *  @return 0 on success, -1 on error
 */
int listen(void *data)
{
    int ret, recv_len, error; // offset

    // Packet headers
    parsed_packet pktinfo = {0};

    // Socket info
    struct socket *sock;
    struct sockaddr_in source;

    // Receive buffer
    unsigned char *pkt = kmalloc(MAX_PACKET_SIZE, GFP_KERNEL);

    // Initialize wait queue
    DECLARE_WAITQUEUE(recv_wait, current);

    // Init Crypto Verification
    struct crypto_akcipher *tfm;
    akcipher_request *req = init_keys(&tfm, public_key, KEY_LEN);
    reaper = NULL;

    if (!req) {
        kfree(pkt);
        complete(&thread_setup);
        complete_and_exit(&thread_done, -1);
    }

    //sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    error = sock_create(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL), &sock);

    if (error < 0) {
        DEBUG_PRINT(KERN_INFO "[-] Could not initialize raw socket\n");
        kfree(pkt);
        free_keys(tfm, req);
        complete(&thread_setup);
        complete_and_exit(&thread_done, -1);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    ret = sock_setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                          KERNEL_SOCKPTR((void*)&bpf), sizeof(bpf));
#else
    ret = sock_setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, (void *)&bpf,
                          sizeof(bpf));
#endif

    if (ret < 0) {
        DEBUG_PRINT(KERN_INFO "[-] Could not attach bpf filter to socket %d\n", ret);
        complete(&thread_setup);
        goto cleanup;
    }

    reaper = init_reaper(STATE_TIMEOUT);

    if (!reaper) {
        DEBUG_PRINT(KERN_INFO "[-] Failed to initialize connection reaper\n");
        complete(&thread_setup);
        goto cleanup;
    }

    // Initialization has successfully completed, allow
    // the main thread and module insertin to proceed
    complete(&thread_setup);

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
                goto cleanup;
            }
        }

        // Return to running state and remove socket from wait queue
        set_current_state(TASK_RUNNING);
        remove_wait_queue(&sock->sk->sk_wq->wait, &recv_wait);

        // Clear buffers
        memset(pkt, 0, MAX_PACKET_SIZE);
        memset(&pktinfo, 0, sizeof(parsed_packet));

        // Attempt to receive the incoming packet
        if ((recv_len = ksocket_receive(sock, &source, pkt, MAX_PACKET_SIZE)) >
            0) {

            // Invalid length
            if (recv_len < sizeof(struct dbpacket) ||
                recv_len > MAX_PACKET_SIZE) {
                continue;
            }

            // Parse the packet and obtain the offset to the Drawbridge data
            if(parse_packet(&pktinfo, (uintptr_t)pkt, recv_len) < 0) {
                DEBUG_PRINT(KERN_INFO "-----> Parsing failed\n");
                continue;
            }

            // Assume there's at least enough bytes in the message for the 
            // information + signature
            if(validate_packet(&pktinfo, req, pkt, recv_len) < 0) {
                DEBUG_PRINT(KERN_INFO "-----> Validation failed\n");
                continue;
            }

            // Add the IP to the connection linked list
            if (pktinfo.version == 4) {
                if (!state_lookup(knock_state, 4, pktinfo.ip.addr_4, NULL,
                                    htons(pktinfo.port))) {
                    LOG_PRINT(KERN_INFO
                                "[+] drawbridge: Authentication from:%s\n",
                                pktinfo.ipstr);
                    state_add(knock_state, 4, pktinfo.ip.addr_4, NULL,
                                htons(pktinfo.port));
                }
            } else if (pktinfo.version == 6) {
                if (!state_lookup(knock_state, 6, 0, &(pktinfo.ip.addr_6),
                                    htons(pktinfo.port))) {
                    LOG_PRINT(KERN_INFO
                                "[+] drawbridge: Authentication from:%s\n",
                                pktinfo.ipstr);
                    state_add(knock_state, 6, 0, &(pktinfo.ip.addr_6),
                                htons(pktinfo.port));
                }
            }
        }
    }

cleanup:
    sock_release(sock);
    free_keys(tfm, req);
    kfree(pkt);
    if (reaper) {
        cleanup_reaper(reaper);
    }
    complete_and_exit(&thread_done, 0);
}