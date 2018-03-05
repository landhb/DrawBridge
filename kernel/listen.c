#include <net/sock.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include "xt_knock.h"
//#include <netinet/ip_icmp.h>

#define MAX_PACKET_SIZE 1024
//#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
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


typedef struct packet {
   struct icmphdr hdr;
   char msg[MAX_PACKET_SIZE - sizeof(struct icmphdr)];
} packet;


int listen(void) {


    int ret,recv_len,error;
    struct socket * sock;
    struct msghdr msg;
    //packet * pkt = kmalloc(sizeof(struct packet), GFP_KERNEL);

    struct sock_fprog bpf = {
        .len = ARRAY_SIZE(code),
        .filter = code,
    };

    //sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    error = sock_create(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL), &sock);

    if (error < 0) {
        printk(KERN_INFO "[-] Could not initialize raw socket\n");
    }

    ret = sock_setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, (void *)&bpf, sizeof(bpf));

    if(ret < 0) {
        printk(KERN_INFO "[-] Could not attach bpf filter to socket\n");
    }

    printk(KERN_INFO "[+] BPF raw socket thread initialized\n")

    while(1) {

        // check exit condition
        if(kthread_should_stop()) {
          break;
        }

        memset(&msg, 0, MAX_PACKET_SIZE-sizeof(struct icmphdr));
        if((recv_len = sock_recvmsg(sock, &msg, 0)) > 0) {

            // Process packet
            printk(KERN_INFO "[+] Got packet!   len:%d    msg:\n", recv_len);
            /*for (i = sizeof(struct icmp)+1; i < recv_len-1; i++) {
                printk("%c", pkt.msg[i]);
            }
            printk("\n"); */

            continue;
        }

    }

    printk(KERN_INFO "[*] returning from child thread\n")
    sock_release(sock);
    return 0;
}
