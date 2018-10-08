/*
	Project: DrawBridge
	Description: Single Packet Authentication Client
	Author: Bradley Landherr
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
#include <linux/udp.h>
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

	// Protocol data
	struct timespec timestamp;
	__be16 port;

} __attribute__( ( packed ) ); 



// Crypto function prototypes
unsigned char *gen_digest(unsigned char *buf, unsigned int len, unsigned int *olen);
unsigned char *sign_data(RSA * pkey, unsigned char *data, unsigned int len, unsigned int *olen);


// calculates checksum
unsigned short in_cksum(unsigned short *addr,int len)
{
	        register int sum = 0;
	        u_short answer = 0;
	        register u_short *w = addr;
	        register int nleft = len;
	        /*
		 *          * Our algorithm is simple, using a 32 bit accumulator (sum), we add
		 *          * sequential 16 bit words to it, and at the end, fold back all the
		 *          * carry bits from the top 16 bits into the lower 16 bits.
		 *          */
	        while (nleft > 1)  {
	                sum += *w++;
	                nleft -= 2;
	        }

		        /* mop up an odd byte, if necessary */
	        if (nleft == 1) {
	        *(u_char *)(&answer) = *(u_char *)w ;
	        sum += answer;
	        }

	        /* add back carry outs from top 16 bits to low 16 bits */
	        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	        sum += (sum >> 16);                     /* add carry */
	        answer = ~sum;                          /* truncate to 16 bits */
	        return(answer);
}

// Creates a psuedo IP header to create the checksum
unsigned short trans_check(unsigned char proto, unsigned char * packet, int length, struct in_addr source_address,struct in_addr dest_address)
{

	struct psuedohdr  {
		struct in_addr source_address;
		struct in_addr dest_address;
		unsigned char place_holder;
		unsigned char protocol;
		unsigned short length;
	} psuedohdr;

	char *psuedo_packet;
	unsigned short answer;

	psuedohdr.protocol = proto;
	psuedohdr.length = htons(length);
	psuedohdr.place_holder = 0;

	psuedohdr.source_address = source_address;
	psuedohdr.dest_address = dest_address;
	  
	if((psuedo_packet = malloc(sizeof(psuedohdr) + length)) == NULL)  {
		perror("malloc");
		exit(1);
	}
	    
	memcpy(psuedo_packet,&psuedohdr,sizeof(psuedohdr));
	memcpy((psuedo_packet + sizeof(psuedohdr)),(char *)packet,length);
	    
	answer = (unsigned short)in_cksum((unsigned short *)psuedo_packet,(length + sizeof(psuedohdr)));
	free(psuedo_packet);
	return answer;
}

// Create unique knock TCP packet
int create_packet(unsigned char * pkt,  int dst_port, int src_port, int proto) {
	struct tcphdr tcp_h;
	struct udphdr udp_h;
	struct packet packet;
	int offset = 0;

	if (proto == IPPROTO_TCP) {

		//tcp_h = (struct tcphdr *)(*pkt);
		//packet = (struct packet *)(*pkt + sizeof(struct tcphdr));

		// Init TCP header
		tcp_h.source = htons(src_port);
		tcp_h.dest = htons(dst_port);
		tcp_h.seq = 0;
		tcp_h.ack_seq = 0;

		tcp_h.res1 = 0;
		tcp_h.doff = (sizeof(struct tcphdr))/4;

		// Flags
		tcp_h.fin = 0;
		tcp_h.syn = 1;
		tcp_h.rst = 0;
		tcp_h.psh = 0;
		tcp_h.ack = 0;
		tcp_h.urg = 0;


		tcp_h.window = htons(3104);
		tcp_h.urg_ptr = 0;
		offset = sizeof(struct tcphdr);
		memcpy(pkt, &tcp_h, offset);
	} else if (proto == IPPROTO_UDP) {

		udp_h.source = htons(src_port);
		udp_h.dest = htons(dst_port);
		offset = sizeof(struct udphdr);
		memcpy(pkt, &udp_h, offset);
	}

	// set drawbridge info
	packet.port = dst_port;
	clock_gettime(CLOCK_REALTIME, &(packet.timestamp));
	memcpy(pkt+offset, &packet, sizeof(struct packet));
	return offset;
}

static inline  void hexdump(unsigned char *buf,unsigned int len) {
	while(len--)
		printf("%02x",*buf++);
	printf("\n");
}


int send_trigger(int proto, char * destination, int dst_port, int src_port, RSA * pkey) {

	int type, offset;
	struct sockaddr_in din;
	struct sockaddr_in6 din6;
	struct sockaddr_in sin;
	//struct sockaddr_in6 sin6;
	int sock,recv_len,send_len, status  = 0;
	void * sig = NULL; // =calloc(2048, 1);
	void * digest = NULL; // calloc(1024, 1);
	unsigned int sig_size, digest_size;

	// Initialize knock packet
	unsigned char * sendbuf = calloc(MAX_PACKET_SIZE, 1);
	offset = create_packet(sendbuf, dst_port, src_port, proto);

	if (offset == 0) {
		printf("[-] Unsupported protocol! Use 'tcp' or 'udp'\n");
	}


	// Sign the timestamp + port to unlock
	digest = (void *)gen_digest((unsigned char *)sendbuf + offset, sizeof(struct packet), &digest_size);
	sig = (void *)sign_data(pkey, digest, digest_size, &sig_size);


	printf("[*] Signature (truncated): ");
	hexdump(sig, 25);
	printf("[*] Digest: ");
	hexdump(digest, digest_size);


	// Create the final packet
	send_len = offset + sizeof(struct packet);
	memcpy(sendbuf + send_len, &sig_size, sizeof(sig_size));
	send_len += sizeof(sig_size);
	memcpy(sendbuf + send_len, sig, sig_size);
	send_len += sig_size;
	memcpy(sendbuf + send_len, &digest_size, sizeof(digest_size));
	send_len += sizeof(digest_size);
	memcpy(sendbuf + send_len, digest, digest_size);
	send_len += digest_size;

	
	// Destination IP information
	if(inet_aton(destination, (struct in_addr *)&(din.sin_addr.s_addr)) == 1) {
		type = 4;
		din.sin_family = AF_INET;
		sock = socket(PF_INET, SOCK_RAW, proto); /*//IPPROTO_RAW */
		din.sin_port = htons(dst_port);
		sin.sin_port = htons(src_port);

		// Calculate the checksum
		inet_aton("10.0.2.15", (struct in_addr *)&(sin.sin_addr.s_addr));

		if (proto == IPPROTO_TCP) {
			((struct tcphdr *)sendbuf)->check = trans_check(proto, sendbuf, send_len, sin.sin_addr, din.sin_addr);
		}
		else if (proto == IPPROTO_UDP) {
			((struct udphdr *)sendbuf)->len = htons((short)send_len);
			((struct udphdr *)sendbuf)->check = trans_check(proto, sendbuf, send_len, sin.sin_addr, din.sin_addr);
		}

	} else if (inet_pton(AF_INET6, destination, &(din6.sin6_addr)) == 1) {
		type = 6;
		sock = socket(PF_INET6, SOCK_RAW, proto); /*//IPPROTO_RAW */
		din6.sin6_family = AF_INET6;
		// When using an IPv6 raw socket, sin6_port must be set to 0 to avoid an EINVAL ("Invalid Argument") error. 
		din6.sin6_port = 0;
	} else {
		fprintf(stderr, "[-] Could not parse IP Address.\n");
		goto cleanup;
	}
	

	if (sock < 0) {
		fprintf(stderr, "[-] Could not initialize raw socket: %s\n", strerror(errno));
		free(sig);
		free(sendbuf);
		free(digest);
		RSA_free(pkey);
		return -1;
	} 

	if(type == 4){
		if((recv_len = sendto(sock, (const void * )sendbuf, send_len, MSG_DONTWAIT, (struct sockaddr *)&din, sizeof(din))) < 0) {
			fprintf(stderr, "[-] Write error: %s\n", strerror(errno));
		} else {
			fprintf(stderr, "[+] Sent packet!   len:%d\n", recv_len);
		}
	}
	else if(type == 6){
		if((recv_len = sendto(sock, (const void * )sendbuf, send_len, MSG_DONTWAIT, (struct sockaddr *)&din6, sizeof(din6))) < 0) {
			fprintf(stderr, "[-] Write error IPv6: %s\n", strerror(errno));
		} else {
			fprintf(stderr, "[+] Sent packet!   len:%d\n", recv_len);
		}
	}

cleanup:
	close(sock);
	free(sig);
	free(sendbuf);
	free(digest);
	RSA_free(pkey);
	pkey = NULL;
	return status;
}

void print_usage() {
	printf("\n[!] Please provide a target IP address and port\n\nUsage: sudo ./bridge [tcp||udp] [SERVER] [PORT TO UNLOCK] [SRC_PORT] [PATH TO CERT]\n\n"
	"Example Unlocking SSH (port 22) on localhost: \n\tsudo ./bridge udp 127.0.0.1 22 53251 ~/.bridge/private.pem\n\n");
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
	int src, dst;
	FILE * pFile = NULL;
	RSA *hold = NULL, * pPrivKey = NULL;   
	char * passwd = NULL;
	long conv;
	int proto;


	if(argc < 5){
		print_usage();
		return -1;
	} 

	if (strncmp(argv[1], "udp", strlen(argv[1]) > strlen("udp") ? strlen("udp") : strlen(argv[1])) == 0) {
		proto = IPPROTO_UDP;
	} else if (strncmp(argv[1], "tcp", strlen(argv[1]) > strlen("tcp") ? strlen("tcp") : strlen(argv[1])) == 0) {
		proto = IPPROTO_TCP;
	}

	errno = 0;
	conv = strtol(argv[3], &p, 10);

	// Check for errors: e.g., the string does not represent an integer
	// or the integer is larger than 65535
	if (errno != 0 || *p != '\0' || conv > MAX_PACKET_SIZE) {
		print_usage();
		return -1;
	} 

	dst = conv; 
	errno = 0;
	conv = strtol(argv[4], &p, 10);

	// Check for errors: e.g., the string does not represent an integer
	// or the integer is larger than 65535
	if (errno != 0 || *p != '\0' || conv > MAX_PACKET_SIZE) {
		print_usage();
		return -1;
	} 

	// Continue on proper input
   	src = conv;
	pPrivKey = NULL;
	passwd = new_get_pass(argv[5]);
	printf("\n");
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();


	if((pFile = fopen(argv[5],"rt")) && 
		(PEM_read_RSAPrivateKey(pFile,&pPrivKey,NULL,passwd))) {
		printf("[*] Sending SPA packet to: %s to unlock port %d\n", argv[2], atoi(argv[3]));
		send_trigger(proto, argv[2], dst, src, pPrivKey);
	} else {
		fprintf(stderr,"[!] Cannot read %s\n", argv[5]);
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