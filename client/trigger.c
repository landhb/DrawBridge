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
#include <sys/types.h>

#define MAX_PACKET_SIZE 65535
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define isascii(c) ((c & ~0x7F) == 0)


/*
 * Public key cryptography signature data
 */
typedef struct pkey_signature {
	__u8 *s;			/* Signature */
	__u32 s_size;		/* Number of bytes in signature */
	__u8 digest[SHA_DIGEST_LENGTH];
	__u8 digest_size;		/* Number of bytes in digest */
} pkey_signature;


// Must be packed so that the compiler doesn't byte align the structure
// Ignoring the ethernet header and IP header here, we'll let the kernel handle it
struct packet {
	struct tcphdr tcp_h;
	
	// Protocol data
	pkey_signature sig;
	__u32 timestamp;
	__be16 port;

} __attribute__( ( packed ) ); 


// Function prototype, implemented in crypto.c
int sign_data(
		const void *buf,    /* input data: byte array */
		size_t buf_len, 
		void *pkey,         /* input private key: byte array of the PEM representation */
		size_t pkey_len,
		void **out_sig,     /* output signature block, allocated in the function */
		size_t *out_sig_len,
		void **out_digest,
		size_t *out_digest_len) {


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

	return;

}


int send_trigger(char * destination, int dst_port) {


	struct sockaddr_in din;
	int sock,recv_len,status  = 0;
	struct packet * pkt =  (struct packet *)malloc(sizeof(struct packet));


	// Initialize trigger packet
	bzero(pkt, sizeof(struct packet));
	create_packet(&pkt, dst_port, 12345);
	sign_data(pkt, sizeof(struct packet), pkt->sig->s)

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

void print_usage() {
	printf("\n[!] Please provide a target IP address and port\n\nUsage: sudo ./trigger [SERVER] [PORT TO UNLOCK]\n\n"
	"Example: sudo ./trigger 127.0.0.1 22\n\n");
}

int main(int argc, char ** argv) {

	char *p;
	int num;

	if(argc < 3){
		print_usage();
		return -1;
	} 

	errno = 0;
	long conv = strtol(argv[2], &p, 10);

	// Check for errors: e.g., the string does not represent an integer
	// or the integer is larger than 65535
	if (errno != 0 || *p != '\0' || conv > MAX_PACKET_SIZE) {
		print_usage();
		return -1;
	} 

	// No error
	num = conv;    	

	printf("[!] Sending trigger to: %s to unlock port %d\n", argv[1], atoi(argv[2]));
	send_trigger(argv[1], num);
	return 0;
}