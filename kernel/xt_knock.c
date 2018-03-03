/*
	NetFilter Kernel Module to Support BPF Based Port Knocking
	Auther: Bradley Landherr
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter/x_tables.h>
#include "xt_knock.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bradley Landherr");
MODULE_DESCRIPTION("NetFilter Kernel Module to Support BPF Based Port Knocking");
MODULE_VERSION("0.1");


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
	return xt_register_targets(knock_tg_reg, ARRAY_SIZE(knock_tg_reg));
}


// Exit function to unregister target
static void __exit knock_xt_exit(void) {
	return xt_unregister_targets(knock_tg_reg, ARRAY_SIZE(knock_tg_reg));
}


// Register the initialization and exit functions
module_init(knock_xt_init);
module_exit(knock_xt_exit);