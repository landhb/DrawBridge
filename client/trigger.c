/*
	Project: Trigger
	Description: Single Packet Authentication Client
	Auther: Bradley Landherr
*/

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <linux/tcp.h>

#define MAX_PACKET_SIZE 65535
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define isascii(c) ((c & ~0x7F) == 0)


// Must be packed so that the compiler doesn't byte align the structure
// Ignoring the ethernet header and IP header here, we'll let the kernel handle it
struct packet {
	struct tcphdr tcp_h;
	char msg[MAX_PACKET_SIZE - sizeof(struct tcphdr) - sizeof(struct iphdr) - sizeof(struct ethhdr)];
} __attribute__( ( packed ) ); 


// Create unique trigger TCP packet
void create_packet(struct packet ** pkt,  int dst_port, int src_port) {

	// Init TCP header
	(*pkt)->tcp_h.source = htons(src_port);
	(*pkt)->tcp_h.dest = htons(dst_port);
	(*pkt)->tcp_h.seq = 0;
	(*pkt)->tcp_h.ack_seq = 0;

	(*pkt)->tcp_h.res1 = 0;
	(*pkt)->tcp_h.doff = (sizeof(struct tcphdr))/4;

	// Flags
	(*pkt)->tcp_h.fin = 0;
	(*pkt)->tcp_h.syn = 1;
	(*pkt)->tcp_h.rst = 1;
	(*pkt)->tcp_h.psh = 0;
	(*pkt)->tcp_h.ack = 1;
	(*pkt)->tcp_h.urg = 0;


	(*pkt)->tcp_h.window = htons(5840);
	(*pkt)->tcp_h.check = 0;
	(*pkt)->tcp_h.urg_ptr = 1;

	printf("[*] Built trigger payload\n");

}


int send_trigger(char * destination) {


	struct sockaddr_in din;
	int sock,recv_len,status  = 0;
	struct packet * pkt =  (struct packet *)malloc(sizeof(struct packet));


	// Initialize trigger packet
	bzero(pkt, sizeof(struct packet));
	create_packet(&pkt, 1234, 12345);


	// Create the RAW socket
	sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); /*//IPPROTO_RAW */

	if (sock < 0) {
		fprintf(stderr, "[-] Could not initialize raw socket: %s\n", strerror(errno));
		free(pkt);
		return -1;
	} 

	// Destination IP information
	din.sin_family = AF_INET;
	din.sin_port = htons(80);
	din.sin_addr.s_addr = inet_addr(destination); 

	if((recv_len = sendto(sock, (const void * )pkt, sizeof(struct packet), MSG_DONTWAIT, (struct sockaddr *)&din, sizeof(din))) < 0) {
		fprintf(stderr, "[-] Write error: %s\n", strerror(errno));
	} else {
		fprintf(stderr, "[+] Sent packet!   len:%d\n", recv_len);
	}


	close(sock);
	free(pkt);
	return status;
}


int main(int argc, char ** argv) {

	if(argc < 2){
		printf("\n[!] Please provide a target IP address\n\nUsage: sudo ./trigger 127.0.0.1\n\n");
		return -1;
	} 

	printf("[!] Sending trigger to: %s\n", argv[1]);
	send_trigger(argv[1]);
	return 0;
}