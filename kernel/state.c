/*
		Implements state functions for ip4_conntrack_state and ip6_conntrack_state
		Author: Bradley Landherr
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rwlock.h>
#include <linux/rculist.h>
#include <linux/timer.h>

#include "xt_knock.h"

/* -----------------------------------------------
			IPv4 Functions
   ----------------------------------------------- */

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


/* -----------------------------------------------
				Reaper Timeout Functions
   ----------------------------------------------- */

// Callback function for the reaper: removes expired connections
void reap_expired_connections(ip4_conntrack_state * head4, ip6_conntrack_state * head6, unsigned int timeout) {
	ip4_conntrack_state	 * state_one;
	ip6_conntrack_state	 * state_two;

	rcu_read_lock();

	list_for_each_entry_rcu(state, &(head->list), list) {

		if(state->src == src && state->port == port) {
			return 1;
		}
	}
	rcu_read_unlock();

	return 0;
}


// Initializes the reaper callback
struct timer_list * init_reaper(ip4_conntrack_state * head4, ip6_conntrack_state * head6, unsigned int timeout) {

	struct timer_list * my_timer = (struct timer_list *)kmalloc(sizeof(struct timer_list), GFP_KERNEL);

	// setup timer to callback reap_expired
	setup_timer(my_timer, reap_expired_connections, head4, head6, timeout);

	// Set the timeout value
	mod_timer(my_timer, jiffies + msecs_to_jiffies(timeout));

	return my_timer;

}

// Cleans up and removes the timer
void cleanup_reaper(struct timer_list * my_timer) {
	del_timer(my_timer);
	kfree((void *)my_timer);
}

