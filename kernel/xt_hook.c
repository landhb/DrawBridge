/** 
* @file xt_hook.c
* @brief Entrypoint for Drawbridge - NetFilter Kernel Module to Support 
* BPF Based Single Packet Authentication
*
* @author Bradley Landherr
*
* @date 04/11/2018
*/
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/errno.h> // https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/errno-base.h for relevent error codes
#include <linux/byteorder/generic.h>
#include <linux/rculist.h>
#include <linux/timer.h>
#include <linux/err.h>

// Version handling
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/task.h>
#include <net/netfilter/nf_conntrack.h>
#endif

// Netfilter headers
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include "drawbridge.h"
#include "compat.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bradley Landherr https://github.com/landhb");
MODULE_DESCRIPTION(
    "NetFilter Kernel Module to Support BPF Based Single Packet Authentication");
MODULE_VERSION("0.1");
MODULE_ALIAS("drawbridge");
MODULE_ALIAS("ip_conntrack_drawbridge");

#define MODULE_NAME "drawbridge"
#define MAX_PORTS 10

// Companion thread
struct task_struct *raw_thread;

// defined in xt_state.c
extern conntrack_state *knock_state;

// Global configs
static unsigned short ports[MAX_PORTS] = { 0 };
static unsigned int ports_c = 0;

// Define module port list argument
module_param_array(ports, ushort, &ports_c, 0400);
MODULE_PARM_DESC(ports, "Port numbers to require knocks for");

static struct nf_hook_ops pkt_hook_ops __read_mostly = {
    .pf         = NFPROTO_IPV4,
    .priority   = NF_IP_PRI_FIRST,
    .hooknum    = NF_INET_LOCAL_IN,
    .hook       = &hook_wrapper_v4,
};

static struct nf_hook_ops pkt_hook_ops_v6 __read_mostly = {
    .pf         = NFPROTO_IPV6,
    .priority   = NF_IP_PRI_FIRST,
    .hooknum    = NF_INET_LOCAL_IN,
    .hook       = &hook_wrapper_v6,
};

/**
 *  @brief Determine if an incoming connection should be accepted
 *
 *  Iterates over the guarded ports defined in the configuration,
 *  if an incoming connection is destined for a guarded port, performs a state
 *  lookup to determine if the source has previously authenticated.
 *
 *  @return NF_ACCEPT/NF_DROP
 */
static unsigned int conn_state_check(int type, __be32 src,
                                     struct in6_addr *src_6, __be16 dest_port)
{
    unsigned int i;

    for (i = 0; i < ports_c && i < MAX_PORTS; i++) {
        // Check if packet is destined for a port on our watchlist
        if (dest_port == htons(ports[i])) {
            if (type == 4 &&
                state_lookup(knock_state, 4, src, NULL, dest_port)) {
                return NF_ACCEPT;
            } else if (type == 6 &&
                       state_lookup(knock_state, 6, 0, src_6, dest_port)) {
                return NF_ACCEPT;
            }

            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

/**
 *  @brief IPv6 Hook
 *
 *  Determines if a connection is NEW fist, ESTABLISHED connections will be ignored.
 *  Then determines if the connection is UDP/TCP before handing it off to 
 *  conn_state_check to make the authorization decision.
 *
 *  @return NF_ACCEPT/NF_DROP
 */
static unsigned int pkt_hook_v6(struct sk_buff *skb)
{
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct ipv6hdr *ipv6_header = (struct ipv6hdr *)skb_network_header(skb);

    // We only want to look at NEW connections
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
    if (skb->nfctinfo == IP_CT_ESTABLISHED &&
        skb->nfctinfo == IP_CT_ESTABLISHED_REPLY) {
        return NF_ACCEPT;
    }
#else
    if ((skb->_nfct & NFCT_INFOMASK) == IP_CT_ESTABLISHED &&
        (skb->_nfct & NFCT_INFOMASK) == IP_CT_ESTABLISHED_REPLY) {
        return NF_ACCEPT;
    }
#endif

    // Unsuported IPv6 encapsulated protocol
    if (ipv6_header->nexthdr != 6 && ipv6_header->nexthdr != 17) {
        return NF_ACCEPT;
    }

    // UDP
    if (ipv6_header->nexthdr == 17) {
        udp_header = (struct udphdr *)skb_transport_header(skb);
        return conn_state_check(6, 0, &(ipv6_header->saddr), udp_header->dest);
    }

    // TCP
    tcp_header = (struct tcphdr *)skb_transport_header(skb);
    return conn_state_check(6, 0, &(ipv6_header->saddr), tcp_header->dest);
}

/**
 *  @brief IPv4 Hook
 *
 *  Determines if a connection is NEW fist, ESTABLISHED connections will be ignored.
 *  Then determines if the connection is UDP/TCP before handing it off to 
 *  conn_state_check to make the authorization decision.
 *
 *  @return NF_ACCEPT/NF_DROP
 */
static unsigned int pkt_hook_v4(struct sk_buff *skb)
{
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

    // We only want to look at NEW connections
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
    if (skb->nfctinfo == IP_CT_ESTABLISHED &&
        skb->nfctinfo == IP_CT_ESTABLISHED_REPLY) {
        return NF_ACCEPT;
    }
#else
    if ((skb->_nfct & NFCT_INFOMASK) == IP_CT_ESTABLISHED &&
        (skb->_nfct & NFCT_INFOMASK) == IP_CT_ESTABLISHED_REPLY) {
        return NF_ACCEPT;
    }
#endif

    // Unsuported IPv4 encapsulated protocol
    if (ip_header->protocol != 6 && ip_header->protocol != 17) {
        return NF_ACCEPT;
    }

    // UDP
    if (ip_header->protocol == 17) {
        udp_header = (struct udphdr *)skb_transport_header(skb);
        return conn_state_check(4, ip_header->saddr, NULL, udp_header->dest);
    }

    // TCP
    tcp_header = (struct tcphdr *)skb_transport_header(skb);
    return conn_state_check(4, ip_header->saddr, NULL, tcp_header->dest);
}

/**
 *  @brief Drawbridge module loading/initialization.
 *
 *  Installs netfilter hooks, and creates listener kernel thread. 
 *
 *  @return 0 on success, !0 on error
 */
static int __init nf_conntrack_knock_init(void)
{
    int ret, ret6;
    raw_thread = NULL;

    // Initialize our memory
    if ((knock_state = init_state()) == NULL) {
        return -ENOMEM;
    }

    // Start kernel thread raw socket to listen for SPA packets
    raw_thread = kthread_create(&listen, NULL, MODULE_NAME);

    if (IS_ERR(raw_thread)) {
        DEBUG_PRINT(KERN_INFO "[-] drawbridge: Unable to start child thread\n");
        return PTR_ERR(raw_thread);
    }

    // Increments usage counter - preserve structure even on exit
    get_task_struct(raw_thread);

    // Now it is safe to start kthread - exiting from it doesn't destroy its struct.
    wake_up_process(raw_thread);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    ret = nf_register_net_hook(&init_net, &pkt_hook_ops);
    ret6 = nf_register_net_hook(&init_net, &pkt_hook_ops_v6);
#else
    ret = nf_register_hook(&pkt_hook_ops);
    ret6 = nf_register_hook(&pkt_hook_ops_v6);
#endif

    if (ret || ret6) {
        DEBUG_PRINT(KERN_INFO "[-] drawbridge: Failed to register hook\n");
        return ret;
    }

    LOG_PRINT(
        KERN_INFO
        "[+] drawbridge: Loaded module into kernel - monitoring %d port(s)\n",
        ports_c);
    return 0;
}

/**
 *  @brief Drawbridge module unloading/cleanup.
 *
 *  Unregisters netfilter hooks, and stops the listener thread. 
 *
 */
static void __exit nf_conntrack_knock_exit(void)
{
    int err = 0;

    if (raw_thread) {
        err = kthread_stop(raw_thread);
        put_task_struct(raw_thread);
        raw_thread = NULL;
        DEBUG_PRINT(KERN_INFO "[*] drawbridge: stopped counterpart thread\n");

    } else {
        DEBUG_PRINT(KERN_INFO "[!] drawbridge: no kernel thread to kill\n");
    }

    if (knock_state) {
        cleanup_states(knock_state);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hook(&init_net, &pkt_hook_ops);
    nf_unregister_net_hook(&init_net, &pkt_hook_ops_v6);
#else
    nf_unregister_hook(&pkt_hook_ops);
    nf_unregister_hook(&pkt_hook_ops_v6);
#endif

    LOG_PRINT(KERN_INFO
              "[*] drawBridge: Unloaded Netfilter module from kernel\n");
    return;
}

// Register the initialization and exit functions
module_init(nf_conntrack_knock_init);
module_exit(nf_conntrack_knock_exit);