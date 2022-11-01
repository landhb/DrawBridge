#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/wait.h>
#include <linux/filter.h>
#include <linux/uio.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
/**
 *  sk_filter_release - Release a socket filter
 *  @fp: the sk_filter to free
 */
static void sk_filter_release(struct sk_filter *fp) {
    struct bpf_prog *prog = fp->prog;
    struct sock_fprog_kern *fprog = NULL;
    
    // Free orig filter
    if ((fprog = prog->orig_prog) != NULL) {
        kfree(fprog->filter);
        kfree(fprog);
    }

    // Free BPF program
    bpf_prog_free(prog);

    // Free the sk_filter
    kfree(fp);
}

/**
 *  sk_filter_release_rcu - Release a socket filter by rcu_head
 *  @rcu: rcu_head that contains the sk_filter to free
 */
static void sk_filter_release_rcu(struct rcu_head *rcu) {
    struct sk_filter *fp = container_of(rcu, struct sk_filter, rcu);
    sk_filter_release(fp);
}

/**
 * __sk_filter_charge
 *
 * @brief Try to charge the socket memory if there is space available
 * @return true on success, false otherwise
 */
static bool __sk_filter_charge(struct sock *sk, struct sk_filter *fp)
{
    u32 filter_size = bpf_prog_size(fp->prog->len);

    // same check as in sock_kmalloc() 
    if (filter_size <= sysctl_optmem_max &&
        atomic_read(&sk->sk_omem_alloc) + filter_size < sysctl_optmem_max) {
        atomic_add(filter_size, &sk->sk_omem_alloc);
        return true;
    }
    return false;
}

/**
 * Uncharge the socket by decrement it's other memory counter
 * and freeing any filter when the reference count has dropped
 * to zero.
 */
static void db_sk_filter_uncharge(struct sock *sk, struct sk_filter *fp) {
    u32 filter_size = bpf_prog_size(fp->prog->len);

    // Decrement the filter's size
    atomic_sub(filter_size, &sk->sk_omem_alloc);

    // Reclaim the filter memory if able
    if (refcount_dec_and_test(&fp->refcnt)) {
        call_rcu(&fp->rcu, sk_filter_release_rcu);
    }
}

/**
 * Charge the socket by incrementing it's sk_omem_alloc counter
 * and incrementing the reference count to the new filter.
 */
static bool db_sk_filter_charge(struct sock *sk, struct sk_filter *fp)
{
    if (!refcount_inc_not_zero(&fp->refcnt))
        return false;

    if (!__sk_filter_charge(sk, fp)) {
        sk_filter_release(fp);
        return false;
    }
    return true;
}

/**
 * sk_attach_prog
 * 
 * @brief Manually attach a BPF program to the socket. Necessary due to 
 * modifications in 5.9, which won't allow SO_ATTACH_FILTER from kernel
 * code, due to more stringent checks that the underlying sock_filter[]
 * address is a usermode pointer.
 * 
 * @note Ported from the non-exported __sk_attach_prog in net/core/filter.c
 * @note The actual underlying issue occurs when sk_attach_filter calls
 * __get_filter, and attempts a copy_from_user() which fails when the sock_fprog
 * contains a kernel pointer.
 */
int sk_attach_prog(struct bpf_prog *prog, struct sock *sk) {
    struct sk_filter *fp = NULL, *old_fp = NULL;

    // Allocate storate for the filter object
    if ((fp = kmalloc(sizeof(*fp), GFP_KERNEL)) == NULL) {
        return -ENOMEM;
    }

    // Assign the filter program
    fp->prog = prog;

    // Bump sk->sk_omem_alloc ensuring it does not exceed
    // sysctl_optmem_max
    if (!db_sk_filter_charge(sk, fp)) {
        kfree(fp);
        return -ENOMEM;
    }

    // Bump the refcount
    refcount_set(&fp->refcnt, 1);

    // Obtain a reference to the old filter if set
    old_fp = rcu_dereference_protected(sk->sk_filter,
                       lockdep_sock_is_held(sk));

    // Re-assign the pointer to the new filter
    rcu_assign_pointer(sk->sk_filter, fp);

    // Free any old old memory
    if (old_fp) {
        db_sk_filter_uncharge(sk, old_fp);
    }

    return 0;
}
#endif