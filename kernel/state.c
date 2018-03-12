/*
		Implements state functions for ip4_conntrack_state and ip6_conntrack_state
		Author: Bradley Landherr
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rwlock.h>
#include <linux/rculist.h>

#include "xt_knock.h"



/* Synchronization structures to prevent threading issues
rwlock_t ip4_lock;
rwlock_t ip6_lock;


void state_sync_init(void) {
		ip4_lock	= RW_LOCK_UNLOCKED;
		ip6_lock 	= RW_LOCK_UNLOCKED;
} */


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

	rcu_read_lock();

	list_for_each_entry_rcu(state, &(head->list), list) {

		if(state->src == src && state->port == port) {
			return 1;
		}
	}
	rcu_read_unlock();

	return 0;
}


// Add a connection state 
void ip4_state_add(ip4_conntrack_state ** head, __be32 src, __be16 port) {

	// Create new node
	ip4_conntrack_state * state = init_ip4_state();

	// set params
	state->port = port;
	state->src = src;

	// add to list
	list_add_rcu(&(state->list), &((*head)->list));
	
	return;
}

