#include <net/sock.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/wait.h> // DECLARE_WAITQUEUE
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/uio.h>  // iov_iter
#include "xt_knock.h"
//#include <netinet/ip_icmp.h>

#define MAX_PACKET_SIZE 65535
#define isascii(c) ((c & ~0x7F) == 0)

// Compiled w/ tcpdump 'icmp[icmptype] == 8' -dd
struct sock_filter code[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 8, 0x00000800 },
	{ 0x30, 0, 0, 0x00000017 },
	{ 0x15, 0, 6, 0x00000001 },
	{ 0x28, 0, 0, 0x00000014 },
	{ 0x45, 4, 0, 0x00001fff },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x50, 0, 0, 0x0000000e },
	{ 0x15, 0, 1, 0x00000008 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

/*
typedef struct packet {
   struct icmphdr hdr;
   char msg[MAX_PACKET_SIZE - sizeof(struct icmphdr)];
} packet; */


static int ksocket_receive(struct socket* sock, struct sockaddr_in* addr, unsigned char* buf, int len)
{
	struct msghdr msg;
	mm_segment_t oldfs;
	int size = 0;
	//struct iov_iter iov;
	struct iovec iov;

	if (sock->sk == NULL) return 0;

	iov.iov_base=buf;
	iov.iov_len=len;


	msg.msg_flags = MSG_DONTWAIT;
	msg.msg_name = addr;
	msg.msg_namelen  = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iocb = NULL;

	iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, len);
	//msg.msg_iter.iov->iov_base = buf;
	//msg.msg_iter.iov->iov_len = len;
	//msg.msg_iovlen=1;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_recvmsg(sock,&msg,msg.msg_flags);
	set_fs(oldfs);

	return size;
}


int listen(void * data) {


	int ret,recv_len,error;
	struct socket * sock;
	struct sockaddr_in source;
	//struct msghdr msg;
	unsigned char * pkt = kmalloc(MAX_PACKET_SIZE, GFP_KERNEL);

	struct sock_fprog bpf = {
		.len = ARRAY_SIZE(code),
		.filter = code,
	};

	// Initialize wait queue
	DECLARE_WAITQUEUE(recv_wait, current);

	//sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	error = sock_create(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL), &sock);

	if (error < 0) {
		printk(KERN_INFO "[-] Could not initialize raw socket\n");
		kfree(pkt);
		return -1;
	}

	ret = sock_setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, (void *)&bpf, sizeof(bpf));

	if(ret < 0) {
		printk(KERN_INFO "[-] Could not attach bpf filter to socket\n");
		sock_release(sock);
		kfree(pkt);
		return -1;
	}



	printk(KERN_INFO "[+] BPF raw socket thread initialized\n");

	while(1) {

		// Add socket to wait queue
		add_wait_queue(&sock->sk->sk_wq->wait, &recv_wait);

		// Socket recv queue empty, set interruptable
		// release CPU and allow scheduler to preempt the thread
		while(skb_queue_empty(&sock->sk->sk_receive_queue)) {

			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(2*HZ);

			// check exit condition
			if(kthread_should_stop()) {

				// Crucial to remove the wait queue before exiting
				set_current_state(TASK_RUNNING);
				remove_wait_queue(&sock->sk->sk_wq->wait, &recv_wait);

				// Cleanup and exit thread
				printk(KERN_INFO "[*] returning from child thread\n");
				sock_release(sock);
				kfree(pkt);
				do_exit(0);
			}
		}

		// Return to running state and remove socket from wait queue
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&sock->sk->sk_wq->wait, &recv_wait);

		memset(pkt, 0, MAX_PACKET_SIZE-sizeof(struct icmphdr));
		if((recv_len = ksocket_receive(sock, &source, pkt, MAX_PACKET_SIZE)) > 0) {

			// Process packet
			printk(KERN_INFO "[+] Got packet!   len:%d\n", recv_len);
		}

	}

	printk(KERN_INFO "[*] returning from child thread\n");
	sock_release(sock);
	kfree(pkt);
	do_exit(0);
}
