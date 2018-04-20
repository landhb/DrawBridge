/*
	Project: DrawBridge
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
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <signal.h>
#include <termios.h>
#include <time.h>

#define MAX_PACKET_SIZE 65535
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define isascii(c) ((c & ~0x7F) == 0)
#define BASE_LENGTH	256


// Must be packed so that the compiler doesn't byte align the structure
// Ignoring the ethernet header and IP header here, we'll let the kernel handle it
struct packet {
	struct tcphdr tcp_h;
	
	// Protocol data
	struct timespec timestamp;
	__be16 port;

} __attribute__( ( packed ) ); 



// Crypto function prototypes
unsigned char *gen_digest(unsigned char *buf, unsigned int len, unsigned int *olen);
unsigned char *sign_data(RSA * pkey, unsigned char *data, unsigned int len, unsigned int *olen);


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

	(*pkt)->port = dst_port;
	clock_gettime(CLOCK_REALTIME, &(*pkt)->timestamp);

	return;

}

static inline  void hexdump(unsigned char *buf,unsigned int len) {
	while(len--)
		printf("%02x",*buf++);
	printf("\n");
}


int send_trigger(char * destination, int dst_port,  RSA * pkey) {


	struct sockaddr_in din;
	int sock,recv_len,send_len, status  = 0;
	struct packet * pkt =  (struct packet *)malloc(sizeof(struct packet));
	void * sig = NULL; // =calloc(2048, 1);
	void * digest = NULL; // calloc(1024, 1);
	void * sendbuf = calloc(MAX_PACKET_SIZE, 1);
	unsigned int sig_size, digest_size;

	// Initialize trigger packet
	bzero(pkt, sizeof(struct packet));
	create_packet(&pkt, dst_port, 12345);


	// Sign the TCP Header + timestamp + port to unlock
	digest = (void *)gen_digest((unsigned char *)pkt, sizeof(struct packet), &digest_size);
	sig = (void *)sign_data(pkey, digest, digest_size, &sig_size);


	printf("Signature:\n");
	hexdump(sig, sig_size);
	printf("\n\nDigest:\n");
	hexdump(digest, digest_size);

	// Create the final packet
	send_len = 0;
	memcpy(sendbuf, pkt, sizeof(struct packet));
	send_len += sizeof(struct packet);
	memcpy(sendbuf + send_len, &sig_size, sizeof(sig_size));
	send_len += sizeof(sig_size);
	memcpy(sendbuf + send_len, sig, sig_size);
	send_len += sig_size;
	memcpy(sendbuf + send_len, &digest_size, sizeof(digest_size));
	send_len += sizeof(digest_size);
	memcpy(sendbuf + send_len, digest, digest_size);
	send_len += digest_size;

	// Create the RAW socket
	sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); /*//IPPROTO_RAW */

	if (sock < 0) {
		fprintf(stderr, "[-] Could not initialize raw socket: %s\n", strerror(errno));
		free(pkt);
		free(sig);
		free(sendbuf);
		free(digest);
		RSA_free(pkey);
		return -1;
	} 

	// Destination IP information
	din.sin_family = AF_INET;
	din.sin_port = htons(dst_port);
	din.sin_addr.s_addr = inet_addr(destination); 

	if((recv_len = sendto(sock, (const void * )sendbuf, send_len, MSG_DONTWAIT, (struct sockaddr *)&din, sizeof(din))) < 0) {
		fprintf(stderr, "[-] Write error: %s\n", strerror(errno));
	} else {
		fprintf(stderr, "[+] Sent packet!   len:%d\n", recv_len);
	}


	close(sock);
	free(pkt);
	free(sig);
	free(sendbuf);
	free(digest);
	RSA_free(pkey);
	pkey = NULL;
	return status;
}

void print_usage() {
	printf("\n[!] Please provide a target IP address and port\n\nUsage: sudo ./bridge [SERVER] [PORT TO UNLOCK] [PATH TO CERT]\n\n"
	"Example: sudo ./bridge 127.0.0.1 22 ~/.bridge/private.pem\n\n");
}



char *new_get_pass(char * path) {

	struct termios term;
	static char *buf = NULL;
	int c, len = BASE_LENGTH, pos = 0;

	// Turn off signals
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	// Turn off terminal ECHO
	tcgetattr(1, &term);
	term.c_lflag &= ~ECHO;
	tcsetattr(1, TCSANOW, &term);

	// Display prompt and recieve password
	buf = realloc(buf, len);
	printf("Enter the password for %s: ", path);
	buf[0] = '\0';
	while ((c=fgetc(stdin)) != '\n') {
		buf[pos++] = (char) c;
		if (pos >= len)
			buf = realloc(buf, (len += BASE_LENGTH));
	}
	buf[pos] = '\0';

	// Restore terminal
	term.c_lflag |= ECHO;
	tcsetattr(1, TCSANOW, &term);
	return buf;
}

int main(int argc, char ** argv) {

	char *p;
	int num;
	FILE * pFile = NULL;
	RSA *hold = NULL, * pPrivKey = NULL;   
	char * passwd = NULL;


	if(argc < 4){
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

	// Continue on proper input
	num = conv;    	
	pPrivKey = NULL;
	passwd = new_get_pass(argv[3]);
	printf("\n");
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();


	if((pFile = fopen(argv[3],"rt")) && 
		(PEM_read_RSAPrivateKey(pFile,&pPrivKey,NULL,passwd))) {
		printf("[*] Sending trigger to: %s to unlock port %d\n", argv[1], atoi(argv[2]));
		send_trigger(argv[1], num, pPrivKey);
	} else {
		fprintf(stderr,"[!] Cannot read %s\n", argv[3]);
		ERR_print_errors_fp(stderr);
		print_usage();
		if(pPrivKey)
			RSA_free(pPrivKey);
	}
	
	if(hold)
		free(hold);
	if(pFile)
		fclose(pFile);
	if(passwd)
		free(passwd);
	return 0;
}