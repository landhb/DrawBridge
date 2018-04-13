/*
	Project: Trigger
	Description: NetFilter Kernel Module to Support BPF Based Single Packet Authentication
	Auther: Bradley Landherr
*/

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/errno.h>   // https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/errno-base.h for relevent error codes
#include <linux/byteorder/generic.h>
#include <linux/rculist.h>
#include <linux/timer.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
#include <linux/sched/task.h>
#endif

// Netfilter headers
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nf_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include "trigger.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bradley Landherr https://github.com/landhb");
MODULE_DESCRIPTION("NetFilter Kernel Module to Support BPF Based Single Packet Authentication");
MODULE_VERSION("0.1");
MODULE_ALIAS("trigger");
MODULE_ALIAS("ip_conntrack_trigger");


DEFINE_SPINLOCK(listmutex);

#define MODULE_NAME "trigger"
#define MAX_PORTS 10

// Companion thread
struct task_struct * raw_thread;

// Globally accessed structs
char * src;
conntrack_state * knock_state;
struct timer_list * reaper;

/*
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
struct net inet_net;
#endif*/

// Global configs
static unsigned short ports[MAX_PORTS];
static unsigned int ports_c = 0;

// Define module port list argument
module_param_array(ports, ushort, &ports_c, 0400);
MODULE_PARM_DESC(ports, "Port numbers to require knocks for");


static unsigned	int pkt_hook_v4(void * priv, struct sk_buff * skb, const struct nf_hook_state * state) {

	unsigned int i, ret = NF_ACCEPT;
	struct iphdr * ip_header = (struct iphdr *)skb_network_header(skb);
	struct tcphdr * tcp_header = (struct tcphdr *)skb_transport_header(skb);


	// We only want to look at NEW connections
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,10,0)
	if(skb->nfctinfo == IP_CT_ESTABLISHED || skb->nfctinfo == IP_CT_ESTABLISHED_REPLY) {
		return NF_ACCEPT;
	}
#else
	if((skb->_nfct & NFCT_INFOMASK) == IP_CT_ESTABLISHED || (skb->_nfct & NFCT_INFOMASK) == IP_CT_ESTABLISHED_REPLY) {
		return NF_ACCEPT;
	}
#endif

	for (i = 0; i < ports_c && i < MAX_PORTS; i++) {

		// Check if packet is destined for a port on our watchlist
		if(tcp_header->dest == htons(ports[i])) {

				memset(src, 0, 16);
				inet_ntoa(src, ip_header->saddr);

				if(state_lookup(knock_state, 4, ip_header->saddr, NULL,  tcp_header->dest)) {
					printk(KERN_INFO	"[!] Connection accepted      source:%s\n", src);
					return NF_ACCEPT;
				}

				return NF_DROP;
		}
	}

	return	ret;	
}



static struct nf_hook_ops pkt_hook_ops __read_mostly	= {
	.pf 		= NFPROTO_IPV4,
	.priority	= 1,
	.hooknum	= NF_INET_LOCAL_IN,
	.hook		= &pkt_hook_v4,
};


// Callback function for the reaper: removes expired connections
void reap_expired_connections(unsigned long timeout) {

	conntrack_state	 * state, *tmp;

	spin_lock(&listmutex);

	list_for_each_entry_safe(state, tmp, &(knock_state->list), list) {

		if(jiffies - state->time_added >= msecs_to_jiffies(timeout)) {
			printk(KERN_INFO "[!] Knock expired\n");
			list_del_rcu(&(state->list));
			spin_unlock(&listmutex);
			//synchronize_rcu();
			kfree(state);
			spin_lock(&listmutex);
			continue;
		}
	}

	spin_unlock(&listmutex);

	// Set the timeout value
	mod_timer(reaper, jiffies + msecs_to_jiffies(timeout));

	return;
} 


// Init function to register target
static int __init nf_conntrack_knock_init(void) {

	int ret;
	raw_thread = NULL;
	reaper = NULL;

	// Initialize our memory
	src = kmalloc(16 * sizeof(char), GFP_KERNEL);
	knock_state = init_state(); 
	//state_sync_init();

	// Start kernel thread raw socket to listen for triggers
	raw_thread = kthread_create(&listen, NULL, MODULE_NAME);

	// Increments usage counter - preserve structure even on exit
	get_task_struct(raw_thread);

	if(IS_ERR(raw_thread)) {
		printk(KERN_INFO "[-] Unable to start child thread\n");
		return PTR_ERR(raw_thread);
	}


	// Now it is safe to start kthread - exiting from it doesn't destroy its struct.
	wake_up_process(raw_thread);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	ret = nf_register_net_hook(&inet_net, &pkt_hook_ops);
#else
	ret = nf_register_hook(&pkt_hook_ops);
#endif

	if(ret) {
		printk(KERN_INFO "[-] Failed to register hook\n");
		return ret;
	} 


	reaper = init_reaper(30000);

	if(!reaper) {
		printk(KERN_INFO "[-] Failed to initialize connection reaper\n");
		return -1;
	}
		

	printk(KERN_INFO "[+] Loaded Knock Netfilter module into kernel - monitoring %d port(s)\n", ports_c);
	return 0;
	
}


// Exit function to unregister target
static void __exit nf_conntrack_knock_exit(void) {

	int err = 0;

	if(raw_thread) {
		//lock_kernel();
		err = kthread_stop(raw_thread);
		put_task_struct(raw_thread);
		raw_thread = NULL;
		printk(KERN_INFO "[*] Stopped counterpart thread\n");
		//unlock_kernel();
	} else {
		printk(KERN_INFO "[!] no kernel thread to kill\n");
	}

	if(reaper) {
		cleanup_reaper(reaper);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	ret = nf_unregister_net_hook(&inet_net, &pkt_hook_ops);
#else
	nf_unregister_hook(&pkt_hook_ops);
#endif

	printk(KERN_INFO "[*] Unloaded Knock Netfilter module from kernel\n");
	return;
}


// Register the initialization and exit functions
module_init(nf_conntrack_knock_init);
module_exit(nf_conntrack_knock_exit);