/*
	Project: DrawBridge
	Description: Implements state functions for the conntrack_state linked list
	Author: Bradley Landherr
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rwlock.h>
#include <linux/rculist.h>
#include <linux/timer.h>

#include "drawbridge.h"

extern spinlock_t listmutex;

static inline int ipv6_addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2)
{
	if(a2 == NULL || a1 == NULL){
		return -1;
	}
	return memcmp(a1, a2, sizeof(struct in6_addr));
}

/* -----------------------------------------------
			State Functions
   ----------------------------------------------- */

conntrack_state	* init_state(void) {

	conntrack_state * state = kmalloc(sizeof(struct conntrack_state), GFP_KERNEL);

	// Zero struct
	memset(state, 0, sizeof(struct conntrack_state));

	// Init list
	INIT_LIST_HEAD(&(state->list));

	return state;
}



// Lookup state of a connection
int state_lookup(conntrack_state * head, int type, __be32 src, struct in6_addr * src_6, __be16 port) {

	conntrack_state	 * state;

	rcu_read_lock();

	list_for_each_entry_rcu(state, &(head->list), list) {

		if(state->type == 4 && state->src.addr_4 == src && state->port == port) {
			rcu_read_unlock();
			return 1;
		} else if (state->type == 6 && ipv6_addr_cmp(&(state->src.addr_6), src_6) == 0 && state->port == port) {
			rcu_read_unlock();
			return 1;
		} 
	}
	rcu_read_unlock();

	return 0;
}


// Add a connection state 
void state_add(conntrack_state ** head, int type, __be32 src, struct in6_addr * src_6, __be16 port) {

	// Create new node
	conntrack_state * state = init_state();

	// set params
	state->type = type;
	if(type == 4) {
		state->src.addr_4 = src;
	} else if (type == 6) {
		memcpy(&(state->src.addr_6), src_6, sizeof(struct in6_addr));
	}
	state->port = port;
	state->time_added = jiffies;

	// add to list
	spin_lock(&listmutex);
	list_add_rcu(&(state->list), &((*head)->list));
	spin_unlock(&listmutex);

	return;
}

void cleanup_states(conntrack_state * head) {

	conntrack_state	 * state, *tmp;
	
	spin_lock(&listmutex);

	list_for_each_entry_safe(state, tmp, &(head->list), list) {

		list_del_rcu(&(state->list));
		spin_unlock(&listmutex);
		kfree(state);
		spin_lock(&listmutex);
		
	}

	spin_unlock(&listmutex);
}


/* -----------------------------------------------
				Reaper Timeout Functions
   ----------------------------------------------- */


// Initializes the reaper callback
struct timer_list * init_reaper(unsigned long timeout) {

	struct timer_list * my_timer = NULL;

	my_timer = (struct timer_list *)kmalloc(sizeof(struct timer_list), GFP_KERNEL);

	if(!my_timer) {
		return NULL;
	}

	// setup timer to callback reap_expired
	setup_timer(my_timer, reap_expired_connections, timeout);

	// Set the timeout value
	mod_timer(my_timer, jiffies + msecs_to_jiffies(timeout));

	return my_timer;

}

// Cleans up and removes the timer
void cleanup_reaper(struct timer_list * my_timer) {
	del_timer(my_timer);
	kfree((void *)my_timer);
} 

