/*
		Implements state functions for ip4_conntrack_state and ip6_conntrack_state
		Author: Bradley Landherr
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include "xt_knock.h"

ip4_conntrack_state	* init_ip4_state(void) {
	ip4_conntrack_state * state = kmalloc(sizeof(struct ip4_conntrack_state), GFP_KERNEL);
	INIT_LIST_HEAD(&(state->list));
	state->src = 0;
	state->port = 0;
	return state;
}


ip6_conntrack_state	* init_ip6_state(void) {
	ip6_conntrack_state	* state = kmalloc(sizeof(struct ip6_conntrack_state), GFP_KERNEL);
	INIT_LIST_HEAD(&(state->list));
	return state;
}


// Lookup state of a connection
int ip4_state_lookup(ip4_conntrack_state * head, __be32 src, __be16 port) {

	ip4_conntrack_state	 * state;

	printk(KERN_INFO "--> Looking up state\n");

	list_for_each_entry(state, &(head->list), list) {
		if(state->src == src && state->port == port) {
			printk(KERN_INFO "--> Found state\n");
			return 1;
		}
	}
	printk(KERN_INFO "--> Didn't find state\n");
	return 0;
}


// Add a connection state 
ip4_conntrack_state	* ip4_state_add(ip4_conntrack_state * head, __be32 src, __be16 port) {

	// Create new node
	ip4_conntrack_state * state = init_ip4_state();

	// set params
	state->port = port;
	state->src = src;

	// add to list
	list_add(&(state->list), &(head->list));

	return head;
}

