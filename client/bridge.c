/*
	Project: DrawBridge
	Description: Single Packet Authentication Client
	Author: Bradley Landherr
*/

#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <linux/if.h>
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
#include <sys/ioctl.h>
#include <signal.h>
#include <termios.h>
#include <time.h>
#include <ctype.h>

#define USAGE                                                                 \
"\nusage:\n"                                                                    \
"  bridge [options]\n\n"                                                     \
"options:\n"                                                                  \
"  -h                  Show this help message\n"                              \
"  -p [protocol]       SPA packet's protocol (Default: udp)\n"           \
"  -d [port_dest]      SPA packet's destination port (Default: 53)\n"           \
"  -s [server_addr]    Target Server's IP Address (required)\n"                         \
"  -u [port_unlock]    Port on Target Server to Unlock  (required)\n"                   \
"  -i [key_path]       Path to private key file (required)\n" \
"\n\n Example Unlocking SSH (port 22) on localhost with a UDP packet sent to port 53: \n\n\tsudo bridge -p udp -s 127.0.0.1 -u 22 -d 53 -i ~/.bridge/private.pem\n\n"

#define MAX_PACKET_SIZE 65535
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
//#define isascii(c) ((c & ~0x7F) == 0)
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


static inline  void hexdump(unsigned char *buf,unsigned int len) {
	while(len--)
		printf("%02x",*buf++);
	printf("\n");
}

unsigned short in_cksum(unsigned short *buf, int nwords) {      

	unsigned long sum;


	sum = 0;
	while(nwords>1){
		sum += *buf++;
		nwords -= 2;
	}

	// pad if there are extra bytes
	if (nwords > 0) {
		sum += ((*buf)&htons(0xFF00));
	}

	sum = (sum >> 16) + (sum &0xffff);

	sum += (sum >> 16);

	return (unsigned short)(~sum);

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
int create_packet(unsigned char * pkt,  int unl_port, int dst_port, int proto) {
	struct tcphdr tcp_h;
	struct udphdr udp_h;
	struct packet packet;
	int offset = 0;

	if (proto == IPPROTO_TCP) {

		// Init TCP header
		tcp_h.source = rand() % (61000 + 1 - 32768) + 32768; // random ephemeral
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
		tcp_h.check = 0; // calculated later
		offset = sizeof(struct tcphdr);
		memcpy(pkt, &tcp_h, offset);
	} else if (proto == IPPROTO_UDP) {

		udp_h.source = rand() % (61000 + 1 - 32768) + 32768; // random ephemeral;
		udp_h.dest = htons(dst_port);
		offset = sizeof(struct udphdr);
		memcpy(pkt, &udp_h, offset);
	}

	// set drawbridge info
	packet.port = unl_port;
	clock_gettime(CLOCK_REALTIME, &(packet.timestamp));
	memcpy(pkt+offset, &packet, sizeof(struct packet));
	return offset;
}


int send_trigger(int proto, char * destination, char * source, int unl_port, int dst_port, RSA * pkey) {

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
	offset = create_packet(sendbuf, unl_port, dst_port, proto);

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

		// Calculate the IP checksum
		inet_aton(source, (struct in_addr *)&(sin.sin_addr.s_addr));

		// set UDP len & checksum if applicable
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
		// When using an IPv6 raw socket, sin6_port must 
		// be set to 0 to avoid an EINVAL ("Invalid Argument") error. 
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


static void Usage() {
	fprintf(stdout, "%s", USAGE);
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

static struct option gLongOptions[] = {
  {"protocol",          required_argument,      NULL,        'p'},
  {"server_addr",     required_argument,      NULL,          's'},
  {"port_unlock",          required_argument,      NULL,     'u'},
  {"pord_dest",        required_argument,      NULL,         'd'},
  {"key_path", required_argument,      NULL,              'i'},
  {"help",          no_argument,            NULL,           'h'},
  {NULL,            0,                      NULL,             0}
};


char * get_interface_ip(char * iface)
{
	int fd;
	struct ifreq ifr;
	
	//char iface[] = int;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	//Type of address to retrieve - IPv4 IP address
	ifr.ifr_addr.sa_family = AF_INET;

	//Copy the interface name in the ifreq structure
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	//display result
	return inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
}

int getdefaultgateway(char * iface)
{
	unsigned long d, g;
	char buf[256];
	int line = 0;
	FILE * f;
	char * p;
	f = fopen("/proc/net/route", "r");
	if(!f)
		return -1;
	while(fgets(buf, sizeof(buf), f)) {
		if(line > 0) {	/* skip the first line */
			p = buf;
			/* grab the interface name */
			while(*p && !isspace(*p)) 
				p++;
			memcpy(iface, buf, p-buf);
			while(*p && isspace(*p))
				p++;
			if(sscanf(p, "%lx%lx", &d, &g)==2) {
				if(d == 0 && g != 0) { /* default */
					fclose(f);
					return 0;
				}
			}
		}
		line++;
	}
	/* default route not found ! */
	if(f)
		fclose(f);
	return -1;
}

int main(int argc, char ** argv) {

	char *p, *src_iface, *src_ip;
	int unl, dst;
	FILE * pFile = NULL;
	RSA *hold = NULL, * pPrivKey = NULL;   
	char * passwd = NULL;
	long conv;
	int proto;
	char * key_path,*protocol,*server,*unlock,*dest_port;
	int option_char = 0;

	// defaults
	protocol = "udp";
	dest_port = "53";
	key_path = NULL;
	server = NULL;
	unlock = NULL;

	
	// Parse and set command line arguments
	while ((option_char = getopt_long(argc, argv, "p:s:hu:d:i:", gLongOptions, NULL)) != -1) {
		switch (option_char) {
			case 'h': // help
				Usage();
				exit(0);
				break;                      
			case 'p': // SPA protocol
				protocol = optarg;
				break;
			case 's': // server
				server = optarg;
				break;
			case 'u': // unlock port
				unlock = optarg;
				break;
			case 'd': // SPA dest port
				dest_port = optarg;
				break;
			case 'i': // key-path
				key_path = optarg;
				break;
			default:
				Usage();
				exit(1);
		}
	}

	// Check all arguments were provided
	if (!key_path || !server || !dest_port) {
		printf("\n[!] You are missing some required arguments\n");
		Usage();
		exit(1);
	}


	if (strncmp(protocol, "udp", strlen(protocol) > strlen("udp") ? strlen("udp") : strlen(protocol)) == 0) {
		proto = IPPROTO_UDP;
	} else if (strncmp(protocol, "tcp", strlen(protocol) > strlen("tcp") ? strlen("tcp") : strlen(protocol)) == 0) {
		proto = IPPROTO_TCP;
	}

	errno = 0;
	conv = strtol(unlock, &p, 10);

	// Check for errors: e.g., the string does not represent an integer
	// or the integer is larger than 65535
	if (errno != 0 || *p != '\0' || conv > MAX_PACKET_SIZE || conv == 0) {
		printf("[!] Please provide a valid port number (1-65535) not %s\n", unlock);
		return -1;
	} 

	unl = conv; 
	errno = 0;
	conv = strtol(dest_port, &p, 10);

	// Check for errors: e.g., the string does not represent an integer
	// or the integer is larger than 65535
	if (errno != 0 || *p != '\0' || conv > MAX_PACKET_SIZE || conv == 0) {
		printf("[!] Please provide a valid port number (1-65535) not %s\n", dest_port);
		return -1;
	} 

	// Grab source address from default interface
	src_iface = calloc(IFNAMSIZ,1);
	if(getdefaultgateway(src_iface) < 0) {
		printf("[!] Could not determine default interface.");
	}
	src_ip = get_interface_ip(src_iface);
	free(src_iface);


	// Continue on proper input
   	dst = conv;
	pPrivKey = NULL;
	passwd = new_get_pass(key_path);
	printf("\n");
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();


	if((pFile = fopen(key_path,"rt")) && 
		(PEM_read_RSAPrivateKey(pFile,&pPrivKey,NULL,passwd))) {
		printf("[*] Sending SPA packet to: %s:%d to unlock port %d\n", server, dst, unl);
		send_trigger(proto, server, src_ip, unl, dst, pPrivKey);
	} else {
		fprintf(stderr,"[!] Cannot read %s\n", key_path);
		ERR_print_errors_fp(stderr);
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