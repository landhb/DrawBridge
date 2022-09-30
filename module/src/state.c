/** 
* @file state.c
* @brief Implements connection state functions for the 
* conntrack_state linked list
*
* @author Bradley Landherr
*
* @date 04/11/2018
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rwlock.h>
#include <linux/rculist.h>
#include <linux/timer.h>
#include <linux/version.h>
#include "drawbridge.h"

/*
 * Globally accessed knock_state list head
 */
conntrack_state *knock_state;

/*
 * Globally access mutex to protect the list
 */
spinlock_t listmutex;
DEFINE_SPINLOCK(listmutex);

/*
 * Reaper thread timer
 */
struct timer_list *reaper;

/**
*  @brief Utility function to compare IPv6 addresses 
*  @param a1 First address, of type in6_addr to compare
*  @param a2 Second address, of type in6_addr to compare
*  @return Zero on a match, otherwise a non-zero integer
*/
static inline int ipv6_addr_cmp(const struct in6_addr *a1,
                                const struct in6_addr *a2)
{
    if (a2 == NULL || a1 == NULL) {
        return -1;
    }
    return memcmp(a1, a2, sizeof(struct in6_addr));
}

/**
 *  @brief Utility function to compare state with parsed_packet
 */
static inline int compare_state_info(struct conntrack_state *state, parsed_packet *info) {
    if (state->type != info->version) {
        return -1;
    }

    if (state->port != info->port) {
        return -1;
    }

    switch(state->type) {
        case 4:
            return state->src.addr_4 == info->ip.addr_4;
        case 6:
            return ipv6_addr_cmp(&state->src.addr_6, &info->ip.addr_6);
        default:
            return -1;
    }
}

/**
*  @brief Utility function to log a new connections to dmesg
*  @param state The SPA conntrack_state associated with this allowed connection
*  @param src IPv4 address to log, if connection is IPv4
*  @param src_6 IPv6 address to log, if connection is IPv6
*  @return Zero on a match, otherwise a non-zero integer
*/
static inline void log_connection(struct conntrack_state *state)
{
    uint8_t buf[512] = {0};

    // Don't log the connection if it could be considered to be the auth
    // packet that we just processed. Implies a slight delay/latency
    // between authorization and the subsequent connection - REVIEW 
    if (jiffies - state->time_added <= 200) {
        return;
    }

    // Convert to human readable to log
    if (state->type == 4) {
        internal_inet_ntoa(buf, sizeof(buf), state->src.addr_4);
    } else if (state->type == 6) {
        internal_inet6_ntoa(buf, sizeof(buf), &state->src.addr_6);
    }

    DEBUG_PRINT("[+] DrawBridge accepted connection - source: %s\n", buf);
}

/**
*  @brief Initializes a new conntrack_state node in memory
*
*  There will be one conntrack_state per authenticated session 
*  As the connection remains established, the state will be periodically
*  updated with a new timestamp to maintain currency and not be destroyed
*  by the reaper thread.
*
*  @return Pointer to the newly allocated conntrack_state struct, NULL on error.
*/
conntrack_state *init_state(void)
{
    conntrack_state *state = NULL;

    if((state = kzalloc(sizeof(struct conntrack_state), GFP_KERNEL)) == NULL) {
        return NULL;
    }

    // Zero struct
    memset(state, 0, sizeof(struct conntrack_state));

    // Init list
    INIT_LIST_HEAD(&(state->list));

    return state;
}

/**
*  @brief Callback for call_rcu, asyncronously frees memory when the
*  RCU grace period ends
*
*  @param rcu The rcu_head for the node being freed, contains all the information necessary 
*  for RCU mechanism to maintain pending updates. 
*/
static void reclaim_state_entry(struct rcu_head *rcu)
{
    struct conntrack_state *state =
        container_of(rcu, struct conntrack_state, rcu);
    kfree(state);
}

/**
*  @brief Update function, to create a copy of a conntrack_state struct, 
*  update it, and then free the old state struct with a later call to call_rcu 
*
*  This is called when a connection has come in and has an authenticated
*  conntrack_state. update_state() will be called to update state->time_updated
*  and maintain currency for ESTABLISHED connections to prevent them from being
*  dropped by the reaper thread. 
*
*  A good reference, on updates in the RCU construct: 
*  http://lse.sourceforge.net/locking/rcu/HOWTO/descrip.html
*
*  @param old_state The conntrack_state to be updated, and later freed
*/
static inline void update_state(conntrack_state *old_state)
{
    // Create new node
    conntrack_state *new_state = init_state();

    if (!new_state) {
        return;
    }

    memcpy(new_state, old_state, sizeof(struct conntrack_state));
    new_state->time_updated = jiffies;

    // obtain lock to list for the replacement
    spin_lock(&listmutex);

    // Replace the old entry
    list_replace_rcu(&old_state->list, &new_state->list);

    // Note that the caller is not permitted to immediately free the newly
    // deleted entry. Instead call_rcu must be used to defer freeing until
    // an RCU grace period has elapsed.
    call_rcu(&old_state->rcu, reclaim_state_entry);

    // Release write lock
    spin_unlock(&listmutex);
    return;
}

/**
*  @brief Function to iterate the conntrack_state list to check
*  if a IP address has properly authenticated with DrawBridge.
*  If so, the conntrack_state will be updated to keep the connection
*  established.
*
*  @param head Beginning of the conntrack_state list
*  @param type IP potocol version, either 4 or 6
*  @param src IPv4 address to log, if connection is IPv4
*  @param src_6 IPv6 address to log, if connection is IPv6
*  @param port Port attempting to be connected to
*/
int state_lookup(conntrack_state *head, parsed_packet *pktinfo)
{
    conntrack_state *state;

    rcu_read_lock();

    list_for_each_entry_rcu (state, &(head->list), list) {
        if (compare_state_info(state, pktinfo)) {
#ifdef DEBUG
            log_connection(state);
#endif
            // Release read lock
            rcu_read_unlock();

            // Update the entry
            update_state(state);
            return 1;
        }
    }
    rcu_read_unlock();

    return 0;
}

/**
*  @brief Function to add a new conntrack_state to the list
*  called upon successful authentication 
*
*  @param head Beginning of the conntrack_state list
*  @param type IP potocol version, either 4 or 6
*  @param src IPv4 address that authenticated, if connection is IPv4
*  @param src_6 IPv6 address that authenticated, if connection is IPv6
*  @param port Port that connections will be allowed to
*/
void state_add(conntrack_state *head, parsed_packet *info)
{
    // Create new node
    conntrack_state *state = init_state();

    // set params
    state->type = info->version;
    if (state->type == 4) {
        state->src.addr_4 = info->ip.addr_4;
    } else if (state->type == 6) {
        state->src.addr_6 = info->ip.addr_6;
    }
    state->port = info->port;
    state->time_added = jiffies;
    state->time_updated = jiffies;

    // add to list
    spin_lock(&listmutex);
    list_add_rcu(&(state->list), &(head->list));
    spin_unlock(&listmutex);

    return;
}

void cleanup_states(conntrack_state *head)
{
    conntrack_state *state, *tmp;

    // Enter critical section
    spin_lock(&listmutex);

    list_for_each_entry_safe (state, tmp, &(head->list), list) {
        // Remove the entry
        list_del_rcu(&(state->list));

        // Note that the caller is not permitted to immediately free the newly
        // deleted entry. Instead call_rcu must be used to defer freeing until
        // an RCU grace period has elapsed.
        call_rcu(&state->rcu, reclaim_state_entry);
    }

    // Exit critical section
    spin_unlock(&listmutex);
}

/* -----------------------------------------------
				Reaper Timeout Functions
   ----------------------------------------------- */

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 153)
void reap_expired_connections_new(struct timer_list *timer)
{
    reap_expired_connections(timer->expires);
    return;
}
#endif

// Initializes the reaper callback
struct timer_list *init_reaper(unsigned long timeout)
{
    struct timer_list *my_timer = NULL;

    my_timer =
        (struct timer_list *)kmalloc(sizeof(struct timer_list), GFP_KERNEL);

    if (!my_timer) {
        return NULL;
    }

    // setup timer to callback reap_expired
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 153)
    timer_setup(my_timer, reap_expired_connections_new, 0);
#else
    setup_timer(my_timer, reap_expired_connections, timeout);
#endif

    // Set the timeout value
    mod_timer(my_timer, jiffies + msecs_to_jiffies(STATE_TIMEOUT));
    return my_timer;
}

// Cleans up and removes the timer
void cleanup_reaper(struct timer_list *my_timer)
{
    del_timer(my_timer);
    kfree((void *)my_timer);
}

/**
*  Callback function for the reaper: removes expired connections
*  @param timeout Conn
*/
void reap_expired_connections(unsigned long timeout)
{
    conntrack_state *state, *tmp;

    DEBUG_PRINT(KERN_INFO "[*] Timer expired, checking connections...\n");

    // Enter critical section
    spin_lock(&listmutex);

    list_for_each_entry_safe (state, tmp, &(knock_state->list), list) {
        if (jiffies - state->time_updated >= msecs_to_jiffies(STATE_TIMEOUT)) {

            // Perform cleanup
            list_del_rcu(&(state->list));

            // Note that the caller is not permitted to immediately free the newly
            // deleted entry. Instead call_rcu must be used to defer freeing until
            // an RCU grace period has elapsed.
            call_rcu(&state->rcu, reclaim_state_entry);
            continue;
        }
    }

    // Exit critical section
    spin_unlock(&listmutex);

    // Set the timeout value
    mod_timer(reaper, jiffies + msecs_to_jiffies(STATE_TIMEOUT));
    DEBUG_PRINT(KERN_INFO "[*] Timer reset.\n");
    return;
}
