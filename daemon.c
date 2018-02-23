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
