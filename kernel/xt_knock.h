#ifndef _LINUX_NETFILTER_XT_KNOCK_H
#define _LINUX_NETFILTER_XT_KNOCK_H 1

struct xt_ipt_knock {
	__u16	win;
};


int listen(void * data);

#endif /* _LINUX_NETFILTER_XT_KNOCK_H */