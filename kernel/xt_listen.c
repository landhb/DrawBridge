/*
	Project: DrawBridge
	Description: Raw socket listener to support Single Packet Authentication
	Author: Bradley Landherr
*/

#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/wait.h> // DECLARE_WAITQUEUE
#include <linux/filter.h>
#include <linux/uio.h>  // iov_iter
#include "drawbridge.h"
#include "key.h"

DEFINE_SPINLOCK(listmutex);
#define isascii(c) ((c & ~0x7F) == 0)

struct timer_list * reaper;
extern conntrack_state * knock_state;


// For both IPv4 and IPv6 compiled w/
// tcpdump "(tcp[tcpflags] == 22 and tcp[14:2] = 5840) or (ip6[40+13] == 22 and ip6[(40+14):2] = 5840)" -dd
struct sock_filter code[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 9, 0x00000800 },
	{ 0x30, 0, 0, 0x00000017 },
	{ 0x15, 0, 13, 0x00000006 },
	{ 0x28, 0, 0, 0x00000014 },
	{ 0x45, 11, 0, 0x00001fff },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x50, 0, 0, 0x0000001b },
	{ 0x15, 0, 8, 0x00000016 },
	{ 0x48, 0, 0, 0x0000001c },
	{ 0x15, 5, 6, 0x000016d0 },
	{ 0x15, 0, 5, 0x000086dd },
	{ 0x30, 0, 0, 0x00000043 },
	{ 0x15, 0, 3, 0x00000016 },
	{ 0x28, 0, 0, 0x00000044 },
	{ 0x15, 0, 1, 0x000016d0 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};




void inet_ntoa(char * str_ip, __be32 int_ip)
{

	if(!str_ip)
		return;

	memset(str_ip, 0, 16);
	sprintf(str_ip, "%d.%d.%d.%d", (int_ip) & 0xFF, (int_ip >> 8) & 0xFF,
							(int_ip >> 16) & 0xFF, (int_ip >> 24) & 0xFF);

	return;
}


void inet6_ntoa(char * str_ip, struct in6_addr * src_6)
{

	if(!str_ip)
		return;

	memset(str_ip, 0, 32);
	sprintf(str_ip, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		                 (int)src_6->s6_addr[0], (int)src_6->s6_addr[1],
		                 (int)src_6->s6_addr[2], (int)src_6->s6_addr[3],
		                 (int)src_6->s6_addr[4], (int)src_6->s6_addr[5],
		                 (int)src_6->s6_addr[6], (int)src_6->s6_addr[7],
		                 (int)src_6->s6_addr[8], (int)src_6->s6_addr[9],
		                 (int)src_6->s6_addr[10], (int)src_6->s6_addr[11],
		                 (int)src_6->s6_addr[12], (int)src_6->s6_addr[13],
		                 (int)src_6->s6_addr[14], (int)src_6->s6_addr[15]);

	return;
}



static int ksocket_receive(struct socket* sock, struct sockaddr_in* addr, unsigned char* buf, int len)
{
	struct msghdr msg;
	mm_segment_t oldfs;
	int size = 0;
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

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_recvmsg(sock,&msg,msg.msg_flags);
	set_fs(oldfs);

	return size;
}


static inline  void hexdump(unsigned char *buf,unsigned int len) {
	while(len--)
		printk("%02x",*buf++);
	printk("\n");
}

// Pointer arithmatic to parse out the signature and digest
static pkey_signature * get_signature(void * pkt, u32 offset) {

	// Allocate the result struct
	pkey_signature * sig = kzalloc(sizeof(pkey_signature), GFP_KERNEL);

	// Get the signature size
	sig->s_size = *(u32 *)(pkt + offset);

	// Sanity check the sig size
	if(sig->s_size > MAX_SIG_SIZE || sig->s_size < 0) {
		return NULL;
	}

	// Copy the signature from the packet
	sig->s = kzalloc(sig->s_size, GFP_KERNEL);
	offset += sizeof(u32);
	memcpy(sig->s, pkt + offset, sig->s_size);

	// Get the digest size
	offset += sig->s_size;
	sig->digest_size = *(u32*)(pkt + offset);

	// Sanity check the digest size
	if(sig->digest_size > MAX_DIGEST_SIZE || sig->digest_size < 0) {
		return NULL;
	}

	// Copy the digest from the packet
	sig->digest = kzalloc(sig->digest_size, GFP_KERNEL);
	offset += sizeof(u32);
	memcpy(sig->digest, pkt + offset, sig->digest_size);

	return sig;

}

static void free_signature(pkey_signature * sig) {
	if(sig->s) {
		kfree(sig->s);
	}
	if(sig->digest) {
		kfree(sig->digest);
	}
	kfree(sig);
}

// Callback function for the reaper: removes expired connections
void reap_expired_connections(unsigned long timeout) {

	conntrack_state	 * state, *tmp;

	spin_lock(&listmutex);

	list_for_each_entry_safe(state, tmp, &(knock_state->list), list) {

		if(jiffies - state->time_added >= msecs_to_jiffies(timeout)) {

			list_del_rcu(&(state->list));
			spin_unlock(&listmutex);
			//synchronize_rcu();
			kfree(state);
			spin_lock(&listmutex);
			continue;
		}
	}

	spin_unlock(&listmutex);

	// Set the timeout value
	mod_timer(reaper, jiffies + msecs_to_jiffies(timeout));

	return;
} 



int listen(void * data) {
	
	
	int ret,recv_len,error, offset, version;

	// Packet headers
	struct ethhdr * eth_h;
	struct iphdr * ip_h;
	struct ipv6hdr * ip6_h;
	struct tcphdr * tcp_h;
	struct packet * res;


	// Socket info
	struct socket * sock;
	struct sockaddr_in source;
	
	struct timespec tm;

	// Buffers
	unsigned char * pkt = kmalloc(MAX_PACKET_SIZE, GFP_KERNEL);
	char * src = kmalloc(32+1, GFP_KERNEL);
	pkey_signature * sig = NULL;
	void * hash = NULL;

	struct sock_fprog bpf = {
		.len = ARRAY_SIZE(code),
		.filter = code,
	};

	// Initialize wait queue
	DECLARE_WAITQUEUE(recv_wait, current);

	// Init Crypto Verification
	struct crypto_akcipher *tfm;
	akcipher_request * req = init_keys(&tfm, public_key, 270);
	reaper = NULL;

	if(!req) {
		kfree(pkt);
		kfree(src);
		return -1;
	}


	//sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	error = sock_create(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL), &sock);

	if (error < 0) {
		printk(KERN_INFO "[-] Could not initialize raw socket\n");
		kfree(pkt);
		kfree(src);
		free_keys(tfm, req);
		return -1;
	}

	ret = sock_setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, (void *)&bpf, sizeof(bpf));

	if(ret < 0) {
		printk(KERN_INFO "[-] Could not attach bpf filter to socket\n");
		sock_release(sock);
		free_keys(tfm, req);
		kfree(pkt);
		kfree(src);
		return -1;
	}


	reaper = init_reaper(STATE_TIMEOUT);

	if(!reaper) {
		printk(KERN_INFO "[-] Failed to initialize connection reaper\n");
		sock_release(sock);
		free_keys(tfm, req);
		kfree(pkt);
		kfree(src);
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
				sock_release(sock);
				free_keys(tfm, req);
				kfree(pkt);
				kfree(src);
				if(reaper) {
					cleanup_reaper(reaper);
				}
				do_exit(0);
			}
		}

		// Return to running state and remove socket from wait queue
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&sock->sk->sk_wq->wait, &recv_wait);

		memset(pkt, 0, MAX_PACKET_SIZE);
		if((recv_len = ksocket_receive(sock, &source, pkt, MAX_PACKET_SIZE)) > 0) {

			if (recv_len < sizeof(struct packet)) {
				continue;
			}

			
			// Check IP version
			eth_h = (struct ethhdr *)pkt;
			if((eth_h->h_proto & 0xFF) == 0x08 && ((eth_h->h_proto >> 8) & 0xFF) == 0x00) 
			{
				version = 4;
				ip_h = (struct iphdr*)(pkt + sizeof(struct ethhdr));
				tcp_h = (struct tcphdr *)(pkt + sizeof(struct ethhdr)+ sizeof(struct iphdr));
				inet_ntoa(src, ip_h->saddr);
				offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct packet);
			}
			else if((eth_h->h_proto & 0xFF) == 0x86 && ((eth_h->h_proto >> 8) & 0xFF) == 0xDD)
			{
				version = 6;
				ip6_h = (struct ipv6hdr *)(pkt + sizeof(struct ethhdr));
				tcp_h = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
				inet6_ntoa(src, &(ip6_h->saddr));
				offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + sizeof(struct packet);
			} 
			
			
			// Process packet
			res = (struct packet *)(pkt + offset - sizeof(struct packet));

			// Parse the packet for a signature
			sig = get_signature(pkt, offset);

			if(!sig) {
				printk(KERN_INFO "[-] Signature not found in packet\n");
				continue;
			}

			// Hash the TCP header + timestamp + port to unlock
			hash = gen_digest((unsigned char *)tcp_h, sizeof(struct tcphdr) + sizeof(struct packet));

			if(!hash) {
				free_signature(sig);
				continue;
			}

			// Check that the hash matches 
			if(memcmp(sig->digest, hash, sig->digest_size) != 0) {
				printk(KERN_INFO "-----> Hash not the same\n");
				free_signature(sig);
				kfree(hash);
				continue;
			} 

			// Verify the signature
			if(verify_sig_rsa(req, sig) != 0) {
				free_signature(sig);
				kfree(hash);
				continue;
			} 

			// Check timestamp (Currently allows 60 sec skew)
			getnstimeofday(&tm);
			if(tm.tv_sec > res->timestamp.tv_sec + 60) {
				free_signature(sig);
				kfree(hash);
				continue;
			}

			// Add the IP to the connection linked list
			if (version == 4)
			{
				if(!state_lookup(knock_state, 4, ip_h->saddr, NULL, htons(res->port))) {
					printk(KERN_INFO "[+] Got auth packet!   len:%d    from:%s\n", recv_len, src);
					state_add(&knock_state, 4, ip_h->saddr, NULL, htons(res->port));
				}
			} 
			else if (version == 6) 
			{
				if(!state_lookup(knock_state, 6, 0, &(ip6_h->saddr), htons(res->port))) {
					printk(KERN_INFO "[+] Got auth packet!   len:%d    from:%s\n", recv_len, src);
					state_add(&knock_state, 6, 0, &(ip6_h->saddr), htons(res->port));
				}
			}

			free_signature(sig);
			kfree(hash);
		}

	}

	sock_release(sock);
	free_keys(tfm, req);
	kfree(pkt);
	kfree(src);
	if(reaper) {
		cleanup_reaper(reaper);
	}
	do_exit(0);
}
