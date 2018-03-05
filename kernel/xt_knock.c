/*
	NetFilter Kernel Module to Support BPF Based Port Knocking
	Auther: Bradley Landherr
*/

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/errno.h>   // https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/errno-base.h for relevent error codes
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include "xt_knock.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bradley Landherr https://github.com/landhb");
MODULE_DESCRIPTION("NetFilter Kernel Module to Support BPF Based Port Knocking");
MODULE_VERSION("0.1");


#define MODULE_NAME "knock"

// Companion thread
struct task_struct * thread;

static unsigned int knock_tg(struct sk_buff *skb, const struct xt_action_param *par) {
	return XT_CONTINUE;
}

static int knock_tg_check(const struct xt_tgchk_param *par) {
	return 0;
}


// Define the iptables TARGET
static struct xt_target knock_tg_reg[] __read_mostly = {
	{
		.name		= "KNOCK",
		.revision 	= 0,
		.family 	= NFPROTO_UNSPEC,
		.target 	= knock_tg,
		.targetsize	= sizeof(struct xt_ipt_knock),
		.table 		= "filter",
		.checkentry	= knock_tg_check,
		.me 		= THIS_MODULE,
	},
};



// Init function to register target
static int __init knock_xt_init(void) {

	thread = NULL;

	// Start kernel thread raw socket to listen for triggers
	thread = kthread_run(&listen, NULL, MODULE_NAME);

	if(IS_ERR(thread)) {
		printk(KERN_INFO "[-] Unable to start child thread\n");
		return PTR_ERR(thread);
	}


	printk(KERN_INFO "[+] Started child thread\n");
	wake_up_process(thread);

	printk(KERN_INFO "[+] Loaded Knock Netfilter module into kernel\n");
	return xt_register_targets(knock_tg_reg, ARRAY_SIZE(knock_tg_reg));
}


// Exit function to unregister target
static void __exit knock_xt_exit(void) {

	int err = 0;

	if(thread==NULL) {
		printk(KERN_INFO MODULE_NAME": no kernel thread to kill\n");
	} else {
		//lock_kernel();
		err = kthread_stop(thread);
		thread = NULL;
		printk(KERN_INFO "[*] Stopped counterpart thread\n");
		//unlock_kernel();
	}


	printk(KERN_INFO "[*] Unloaded Knock Netfilter module from kernel\n");
	return xt_unregister_targets(knock_tg_reg, ARRAY_SIZE(knock_tg_reg));
}


// Register the initialization and exit functions
module_init(knock_xt_init);
module_exit(knock_xt_exit);