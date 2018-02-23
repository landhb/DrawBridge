#include <stdlib.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>

#define MAX_PACKET_SIZE 64
#define ARRAY_SIZE (arr) (sizeof(arr) / sizeof(arr[0]))
#define isascii(c) ((c & ~0x7F) == 0)

struct sock_filter code[] = {};

typedef struck packet {
   struct icmphdr hdr;
   char msg[MAX_PACKET_SIZE - sizeof(struct icmphdr)];
} packet;

int main(int argc, char ** argv) {
   int sock,ret,i,recv_len;
   packet pkt;
   
   struct sock_fprog bpf = {
      .len = ARRAY_SIZE(code),
      .filter = code,
   }
   
   sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   
   if (sock < 0)
      printf("[-] Could not initialize raw socket\n");
   
   ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
   
   if(ret < 0)
      printf("[-] Could not attach bpf filter to socket\n");
   
   while(1) {
      
      if((recv_len = recv(sock, &pkt, sizeof(pkt), 0) {
         printf("[+] Got packet!   len:%d    msg:", recv_len);
      }
      
   }
   close(sock);
}
