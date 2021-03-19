/** 
* @file compat.h
* @brief Kernel Version Specific Prototypes/Compatibility Header
*
* @author Bradley Landherr
*
* @date 03/17/2021
*/
#ifndef _LINUX_DRAWBRIDGE_COMPAT
#define _LINUX_DRAWBRIDGE_COMPAT 1

static unsigned int pkt_hook_v6(struct sk_buff *skb);
static unsigned int pkt_hook_v4(struct sk_buff *skb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static unsigned int hook_wrapper_v4(void *priv, struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    return pkt_hook_v4(skb);
}
static unsigned int hook_wrapper_v6(void *priv, struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    return pkt_hook_v6(skb);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
static unsigned int hook_wrapper_v4(const struct nf_hook_ops *ops,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    return pkt_hook_v4(skb);
}
static unsigned int hook_wrapper_v6(const struct nf_hook_ops *ops,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    return pkt_hook_v6(skb);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
static unsigned int hook_wrapper_v4(const struct nf_hook_ops *ops,
                                    struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *))
{
    return pkt_hook_v4(skb);
}
static unsigned int hook_wrapper_v6(const struct nf_hook_ops *ops,
                                    struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *))
{
    return pkt_hook_v6(skb);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
static unsigned int hook_wrapper_v4(unsigned int hooknum, struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *))
{
    return pkt_hook_v4(skb);
}
static unsigned int hook_wrapper_v6(unsigned int hooknum, struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *))
{
    return pkt_hook_v6(skb);
}
#else
#error "Unsuported kernel version.  Only Linux 3.X and greater."
#endif

#endif /* _LINUX_DRAWBRIDGE_COMPAT */
