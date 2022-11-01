#ifndef DRAWBRIDGE_SK_H
#define DRAWBRIDGE_SK_H 1

/**
 * sk_attach_prog
 * 
 * @brief Manually attach a BPF program to the socket. Necessary due to 
 * modifications in 5.9, which won't allow SO_ATTACH_FILTER from kernel
 * code, due to more stringent checks that the underlying sock_filter[]
 * address is a usermode pointer.
 * 
 * @note Ported from the non-exported __sk_attach_prog in net/core/filter.c
 */
int sk_attach_prog(struct bpf_prog *prog, struct sock *sk);

#endif /* DRAWBRIDGE_SK_H */