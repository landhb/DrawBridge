/** 
* @file listener.c
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
#include "filter.h"
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
// tcpdump "udp dst port 10053 and inbound" -dd
struct sock_filter code[] = {
    { 0x28, 0, 0, 0x0000000c }, { 0x15, 0, 4, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 }, { 0x15, 0, 13, 0x00000011 },
    { 0x28, 0, 0, 0x00000038 }, { 0x15, 8, 11, 0x00002745 },
    { 0x15, 0, 10, 0x00000800 }, { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 8, 0x00000011 }, { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff }, { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x00000010 }, { 0x15, 0, 3, 0x00002745 },
    { 0x28, 0, 0, 0xfffff004 }, { 0x15, 1, 0, 0x00000004 },
    { 0x6, 0, 0, 0x00040000 }, { 0x6, 0, 0, 0x00000000 },
};

// BPF program that immediately returns
// https://web.archive.org/web/20220511125816/https://natanyellin.com/posts/ebpf-filtering-done-right/
struct sock_filter zerocode[] = {
    BPF_STMT(BPF_RET | BPF_K, 0)
};

/**
 * @brief Wrap kernel_recvmsg due to modifications in 4.20+ & 3.19+
 *
 * @param sock Kernel socket to recv on
 * @param buf  Buffer to recv into
 * @param len  Length of provided buffer
 */
static int ksocket_receive(struct socket *sock,
                           unsigned char *buf, int len)
{
    struct msghdr msg;
    int size = 0;
    struct kvec iov;

    if (sock->sk == NULL) {
        return 0;
    }

    // Zero msghdr
    memset(&msg, 0, sizeof(struct msghdr));

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_flags = MSG_DONTWAIT;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
    msg.msg_iocb = NULL;
    iov_iter_kvec(&msg.msg_iter, WRITE, &iov, 1, len);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    msg.msg_iocb = NULL;
    iov_iter_kvec(&msg.msg_iter, WRITE | ITER_KVEC, &iov, 1, len);
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
 * @brief Wrap thread exit due to modifications in 5.17
 *
 * @param value Exit code
 */
void __noreturn thread_exit(int value) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
    kthread_complete_and_exit(&thread_done, value);
#else
    complete_and_exit(&thread_done, value);
#endif
}


/**
 * @brief Wrap SO_ATTACH_FILTER due to modifications in 5.9
 *
 * @param sock Socket to apply filter on
 * @param fprog BPF program to apply
 */
int apply_filter(struct socket *sock, struct sock_fprog *fprog) {
    int ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    struct bpf_prog * prog = NULL;

    // Create the BPF program from our cBPF filter
    if (bpf_prog_create(&prog, (struct sock_fprog_kern *)fprog) != 0) {
        DEBUG_PRINT(KERN_INFO "[-] Could not create unattached filter.\n");
        return -1;
    }

    // Directly attach to the socket
    ret = sk_attach_prog(prog, sock->sk);
    if (ret < 0) {
        bpf_prog_free(prog);
    }
#else
    ret = sock_setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                        (char __user *)fprog, sizeof(struct sock_fprog));
#endif
    return ret;
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
    struct sock_fprog fprog;
    int ret = 0, recv_len, error;

    // Packet headers
    parsed_packet pktinfo = {0};

    // Socket info
    struct socket *sock = NULL;

    // Init pointers
    unsigned char *pkt = NULL;
    akcipher_request *req = NULL;
    struct crypto_akcipher *tfm = NULL;

    // Initialize wait queue and reaper
    DECLARE_WAITQUEUE(recv_wait, current);
    reaper = NULL;

    // Init Crypto Verification
    req = init_keys(&tfm, public_key, KEY_LEN);

    // Allocate receive buffer
    pkt = kmalloc(MAX_PACKET_SIZE, GFP_KERNEL);

    // Sanity check setup
    if (!req || !pkt || !tfm) {
        ret = -1;
        goto cleanup;
    }

    // Create the raw socket listener
    error = sock_create(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL), &sock);
    if (error < 0 || !sock) {
        DEBUG_PRINT(KERN_INFO "[-] Could not initialize raw socket\n");
        ret = -1;
        goto cleanup;
    }

    // Apply the BPF zero program
    fprog.len = ARRAY_SIZE(zerocode);
    fprog.filter = zerocode;
    if ((ret = apply_filter(sock, &fprog)) < 0) {
        DEBUG_PRINT(KERN_INFO "[-] Could not attach bpf zero filter to socket %d\n", ret);
        goto cleanup;
    }

    // Clear the recv queue until nothing is left
    while(ksocket_receive(sock, pkt, MAX_PACKET_SIZE) > 0) {}

    // Apply the actual BPF program. This is an atomic swap
    // with the zero-program that is currently blocking all new
    // packets.
    fprog.len = ARRAY_SIZE(code);
    fprog.filter = code;
    if ((ret = apply_filter(sock, &fprog)) < 0) {
        DEBUG_PRINT(KERN_INFO "[-] Could not attach bpf filter to socket %d\n", ret);
        goto cleanup;
    }

    // Init the reaper thread
    if ((reaper = init_reaper(STATE_TIMEOUT)) == NULL) {
        DEBUG_PRINT(KERN_INFO "[-] Failed to initialize connection reaper\n");
        ret = -1;
        goto cleanup;
    }

    // Initialization has successfully completed, allow
    // the main thread and module insert to proceed
    complete(&thread_setup);
    while (1) {

        // Add socket to wait queue
        add_wait_queue(&sock->sk->sk_wq->wait, &recv_wait);

        // Socket recv queue empty, set interruptable
        // release CPU and allow scheduler to preempt the thread
        while (skb_queue_empty(&sock->sk->sk_receive_queue)) {
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(2 * HZ);

            // Check the thread exit condition. It is
            // crucial to remove the wait queue before exiting
            if (kthread_should_stop()) {
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
        if ((recv_len = ksocket_receive(sock, pkt, MAX_PACKET_SIZE)) > 0) {

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

            // Assume at this point there's at least enough bytes in the message
            // for the information + signature
            if(validate_packet(&pktinfo, req, pkt, recv_len) < 0) {
                DEBUG_PRINT(KERN_INFO "-----> Validation failed\n");
                continue;
            }

            // Add the IP to the connection linked list if not already added
            if (!state_lookup(knock_state, &pktinfo)) {
                LOG_PRINT(KERN_INFO
                            "[+] drawbridge: Authentication from:%s\n",
                            pktinfo.ipstr);
                state_add(knock_state, &pktinfo);
            }
        }
    }

cleanup:
    // Checked internally for NULL
    free_keys(tfm, req);

    if (sock) {
        sock_release(sock);
    }

    if (pkt) {
        kfree(pkt);
    }

    if (reaper) {
        cleanup_reaper(reaper);
    }

    // Allow the main thread to progress
    // and exit
    complete(&thread_setup);
    thread_exit(ret);
}
