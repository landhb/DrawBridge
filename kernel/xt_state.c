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



// Globally accessed knock_state list head
conntrack_state * knock_state;

// Globally access mutex to protect the list
spinlock_t listmutex;
DEFINE_SPINLOCK(listmutex);

// reaper thread timer
struct timer_list * reaper;

static inline int ipv6_addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2)
{
	if(a2 == NULL || a1 == NULL){
		return -1;
	}
	return memcmp(a1, a2, sizeof(struct in6_addr));
}


static inline void log_connection(struct conntrack_state * state, __be32 src, struct in6_addr * src_6) {

	if(state->type == 4 && (jiffies - state->time_added <= 200)) {
		printk(KERN_INFO	"[+] DrawBridge accepted connection - source: %d.%d.%d.%d\n", (src) & 0xFF, (src >> 8) & 0xFF,
							(src >> 16) & 0xFF, (src >> 24) & 0xFF);
	}
	else if (state->type == 6 && (jiffies - state->time_added <= 200)) {
		printk(KERN_INFO	"[+] DrawBridge accepted connection - source: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
		                 (int)src_6->s6_addr[0], (int)src_6->s6_addr[1],
		                 (int)src_6->s6_addr[2], (int)src_6->s6_addr[3],
		                 (int)src_6->s6_addr[4], (int)src_6->s6_addr[5],
		                 (int)src_6->s6_addr[6], (int)src_6->s6_addr[7],
		                 (int)src_6->s6_addr[8], (int)src_6->s6_addr[9],
		                 (int)src_6->s6_addr[10], (int)src_6->s6_addr[11],
		                 (int)src_6->s6_addr[12], (int)src_6->s6_addr[13],
		                 (int)src_6->s6_addr[14], (int)src_6->s6_addr[15]);
	}
}

/* -----------------------------------------------
			State Functions
   ----------------------------------------------- */

conntrack_state	* init_state(void) {

	conntrack_state * state = kzalloc(sizeof(struct conntrack_state), GFP_KERNEL);

	// Zero struct
	memset(state, 0, sizeof(struct conntrack_state));

	// Init list
	INIT_LIST_HEAD(&(state->list));

	return state;
}

/*
	Callback for call_rcu, asyncronously frees memory when the 
	RCU grace period ends
*/
static void reclaim_state_entry(struct rcu_head * rcu) {
	struct conntrack_state * state = container_of(rcu, struct conntrack_state, rcu);
	kfree(state);
}

/*
	Create copy of a state struct, update it, and then RCU replace
*/
static inline void update_state(conntrack_state * old_state) {

	// Create new node
	conntrack_state * new_state = init_state();

	if (!new_state) {
		return;
	}


	//printk(KERN_INFO "Time added timestamp: %lu\n", old_state->time_added);
	memcpy(new_state, old_state, sizeof(struct conntrack_state));
	new_state->time_updated = jiffies;
	
	// obtain lock to list for the replacement
	spin_lock(&listmutex);
	list_replace_rcu(&old_state->list, &new_state->list);
	spin_unlock(&listmutex);

	//printk(KERN_INFO "Updated timestamp: %lu\n", new_state->time_updated);

	return;
}



// Lookup state of a connection, if found re-up timestamp
int state_lookup(conntrack_state * head, int type, __be32 src, struct in6_addr * src_6, __be16 port) {

	conntrack_state	 * state;

	rcu_read_lock();

	list_for_each_entry_rcu(state, &(head->list), list) {

		if(state->type == 4 && state->src.addr_4 == src && state->port == port) {
			update_state(state);
			log_connection(state, src, src_6);
			rcu_read_unlock();
			call_rcu(&state->rcu, reclaim_state_entry);
			return 1;
		} else if (state->type == 6 && ipv6_addr_cmp(&(state->src.addr_6), src_6) == 0 && state->port == port) {
			update_state(state);
			log_connection(state, src, src_6);
			rcu_read_unlock();
			call_rcu(&state->rcu, reclaim_state_entry);
			return 1;
		} 
	}
	rcu_read_unlock();

	return 0;
}


// Add a connection state 
void state_add(conntrack_state * head, int type, __be32 src, struct in6_addr * src_6, __be16 port) {

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
	state->time_updated = jiffies;

	// add to list
	spin_lock(&listmutex);
	list_add_rcu(&(state->list), &(head->list));
	spin_unlock(&listmutex);

	return;
}

void cleanup_states(conntrack_state * head) {

	conntrack_state	 * state, *tmp;
	
	spin_lock(&listmutex);

	list_for_each_entry_safe(state, tmp, &(head->list), list) {

		list_del_rcu(&(state->list));
		spin_unlock(&listmutex);
		call_rcu(&state->rcu, reclaim_state_entry);
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



// 
/**
*  Callback function for the reaper: removes expired connections
*  @param timeout Conn
*/
void reap_expired_connections(unsigned long timeout) {

	conntrack_state	 * state, *tmp;

	spin_lock(&listmutex);
	
	list_for_each_entry_safe(state, tmp, &(knock_state->list), list) {

		if(jiffies - state->time_updated >= msecs_to_jiffies(timeout)) {

			list_del_rcu(&(state->list));
			spin_unlock(&listmutex);
			call_rcu(&state->rcu, reclaim_state_entry);
			spin_lock(&listmutex);
			continue;
		}
	}

	spin_unlock(&listmutex);

	// Set the timeout value
	mod_timer(reaper, jiffies + msecs_to_jiffies(timeout));

	return;
} 

