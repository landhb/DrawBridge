/*
	Project: Trigger
	Description: Raw socket listener to support Single Packet Authentication
	Auther: Bradley Landherr
*/

#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/wait.h> // DECLARE_WAITQUEUE
#include <linux/filter.h>
#include <linux/uio.h>  // iov_iter
#include "xt_knock.h"
//#include <netinet/ip_icmp.h>


#define isascii(c) ((c & ~0x7F) == 0)
char * test;

extern conntrack_state * knock_state;


// Compiled w/ tcpdump "tcp[tcpflags] == 22 and tcp[14:2] = 5840" -dd
struct sock_filter code[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 10, 0x00000800 },
	{ 0x30, 0, 0, 0x00000017 },
	{ 0x15, 0, 8, 0x00000006 },
	{ 0x28, 0, 0, 0x00000014 },
	{ 0x45, 6, 0, 0x00001fff },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x50, 0, 0, 0x0000001b },
	{ 0x15, 0, 3, 0x00000016 },
	{ 0x48, 0, 0, 0x0000001c },
	{ 0x15, 0, 1, 0x000016d0 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};




void inet_ntoa(char * str_ip, __be32 int_ip)
{

	if(!str_ip)
		return;
	else
		memset(str_ip, 0, 16);


	sprintf(str_ip, "%d.%d.%d.%d", (int_ip) & 0xFF, (int_ip >> 8) & 0xFF,
							(int_ip >> 16) & 0xFF, (int_ip >> 24) & 0xFF);

	return;
}




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


void * test_key = 
"\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xBB\x82\x86\x5B\x85\xED\x42"
"\x0C\xF3\x60\x54\x4B\x00\xD6\x6A\x96\x63\x79\x38\x6B\x23\x7F\x5F"
"\xDA\xE3\x30\x37\x3F\x3A\xEB\x13\xBE\x43\x11\x8C\xFC\xA8\x08\x51"
"\x59\x55\x59\xCA\x80\x42\xF6\x8A\x4C\xB7\x69\x48\x8F\x98\xFB\x08"
"\x56\x89\xA1\xB6\x30\xD0\xFE\x71\x73\xCA\x3D\xC1\x92\x89\x98\xD6"
"\xB7\xD3\x7A\x28\x2B\x1E\xFB\x27\xC2\x43\x7B\x6C\x54\x3E\xBB\x26"
"\xF0\x47\x93\x39\x99\xC9\x2F\xE6\x9C\x60\x6E\xDB\x96\x72\xB2\xAB"
"\x3E\xEE\x19\x8E\x99\x29\xBE\x61\x59\x56\x33\xDE\xBD\xDC\x8D\x41"
"\x0E\x2F\x8E\xA4\x93\xF6\xE6\x1E\xFD\x98\x86\xE4\x4B\x8F\xCB\x2E"
"\x9D\x65\x24\xAE\x20\x79\xE2\x5C\x97\x3D\xF3\x68\x26\x0A\x2A\x6B"
"\x65\x01\xE4\xA4\xB9\xD5\x8E\xEF\xAD\xFF\x46\x80\xEA\xDD\x95\x88"
"\x51\x90\x86\xEB\xBC\x1D\xC9\xED\x3F\x93\x8B\xA9\xD6\x0A\xA2\x57"
"\xC8\x2E\xAF\xCD\x93\xBF\xA9\x5B\xB4\xF3\x64\xEA\x9C\x6A\x5A\x33"
"\x48\xDB\x37\x9C\xF9\x86\xF7\xB3\x52\xD5\xA2\x07\xAE\x1C\x23\x29"
"\x34\xBA\x37\xC8\xC4\x98\xF0\x9C\x0B\x7F\x82\xCE\x79\x16\xD2\x33"
"\x55\xC1\x4E\x52\x42\x91\x19\xAF\x18\xA1\x26\x99\x9F\xF3\x46\x2A"
"\x78\xBE\xCB\x90\xD1\x68\xEB\xCE\x9D\x02\x03\x01\x00\x01";



int listen(void * data) {

	
	int ret,recv_len,error;
	struct socket * sock;
	struct sockaddr_in source;
	struct packet * res;
	unsigned char * pkt = kmalloc(MAX_PACKET_SIZE, GFP_KERNEL);
	char * src = kmalloc(16 * sizeof(char), GFP_KERNEL);

	struct sock_fprog bpf = {
		.len = ARRAY_SIZE(code),
		.filter = code,
	};

	// Initialize wait queue
	DECLARE_WAITQUEUE(recv_wait, current);

	// Init Crypto Verification
	struct crypto_akcipher *tfm;
	akcipher_request * req = init_keys(&tfm, test_key, 269);


	//sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	error = sock_create(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL), &sock);

	if (error < 0) {
		printk(KERN_INFO "[-] Could not initialize raw socket\n");
		kfree(pkt);
		free_keys(tfm, req);
		return -1;
	}

	ret = sock_setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, (void *)&bpf, sizeof(bpf));

	if(ret < 0) {
		printk(KERN_INFO "[-] Could not attach bpf filter to socket\n");
		sock_release(sock);
		free_keys(tfm, req);
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
				free_keys(tfm, req);
				kfree(pkt);
				kfree(src);
				do_exit(0);
			}
		}

		// Return to running state and remove socket from wait queue
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&sock->sk->sk_wq->wait, &recv_wait);

		memset(pkt, 0, MAX_PACKET_SIZE-sizeof(struct icmphdr));
		if((recv_len = ksocket_receive(sock, &source, pkt, MAX_PACKET_SIZE)) > 0) {


			res = (struct packet *)pkt;
			inet_ntoa(src, res->ip_h.saddr);

			// Process packet
			printk(KERN_INFO "[+] Got packet!   len:%d    from:%s\n", recv_len, src);

			verify_sig_rsa(req, res->sig);

			if(!state_lookup(knock_state, 4, res->ip_h.saddr, NULL, htons(1234))) {
				state_add(&knock_state, 4, res->ip_h.saddr, NULL, htons(1234));
			}

		}

	}

	printk(KERN_INFO "[*] returning from child thread\n");
	sock_release(sock);
	free_keys(tfm, req);
	kfree(pkt);
	kfree(src);
	do_exit(0);
}
