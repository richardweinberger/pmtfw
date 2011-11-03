/*
 * pmtfw.c - A poor man's TCP firewall
 * (c) 2011 Richard Weinberger <richard@nod.at>
 * 
 * License: GPLv2 (http://www.gnu.org/licenses/gpl-2.0.html)
 */	

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PKGSIZ	512
#define MAX_ALLOWED_IPS 32

static int fd_raw_read;
static int fd_raw_write;

static bool foreground = false;
static char *bind_interface;

static struct in_addr allowed_ips[MAX_ALLOWED_IPS];
static unsigned int num_allowed_ips;

struct pseudohdr {
	u_int32_t src;
	u_int32_t dst;
	u_int8_t zero;
	u_int8_t proto;
	u_int16_t len;
};

static u_int16_t cksum(u_int16_t *buf, int nbytes)
{
	u_int32_t sum = 0;
	u_int16_t oddbyte;

	while(nbytes > 1){
		sum += *buf++;
		nbytes -= 2;
	}

	if(nbytes == 1){
		oddbyte = 0;
		*((u_int16_t *)&oddbyte) = *(u_int16_t *)buf;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (u_int16_t)~sum;
}

static int send_rst(u_int32_t src, u_int32_t dst, u_int16_t sport, u_int16_t dport, u_int32_t seq)
{
	struct pseudohdr *phdr;
	struct tcphdr *thdr;
	struct iphdr *ihdr;
	struct sockaddr_in target;

	char *tcp_packet;
	char *ip_packet;

	tcp_packet = calloc(1, sizeof(*phdr) + sizeof(*thdr));
	ip_packet = calloc(1, sizeof(*ihdr) + sizeof(*thdr));

	assert(tcp_packet && ip_packet);

	phdr = (struct pseudohdr *)tcp_packet;
	thdr = (struct tcphdr *)(tcp_packet + sizeof(*phdr));

	phdr->src = src;
	phdr->dst = dst;
	phdr->zero = 0;
	phdr->proto = IPPROTO_TCP;
	phdr->len = htons(sizeof(*thdr));
	thdr->source = sport;
	thdr->dest = dport;
	thdr->doff = 5;
	thdr->rst = 1;
	thdr->seq = seq;
	thdr->ack_seq = 0;
	thdr->window = 0;
	thdr->check = cksum((u_int16_t *)tcp_packet, sizeof(*phdr) + sizeof(*thdr));

	ihdr = (struct iphdr *)ip_packet;
	ihdr->saddr = phdr->src;
	ihdr->daddr = phdr->dst;
	ihdr->version = 4;
	ihdr->ihl = 5;
	ihdr->tos = 0;
	ihdr->tot_len = sizeof(*ihdr) + sizeof(*thdr);
	ihdr->id = htons((unsigned)rand());
	ihdr->ttl = 64;
	ihdr->protocol = IPPROTO_TCP;

	memcpy(ip_packet + sizeof(*ihdr), tcp_packet + sizeof(*phdr), sizeof(*thdr));

	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_addr.s_addr = dst;
	target.sin_port = dport;

	if(sendto(fd_raw_write, ip_packet, sizeof(*ihdr) + sizeof(*thdr), 0, (struct sockaddr *)&target, sizeof(target)) < 0)
		perror("FATAL: sendto");


	free(tcp_packet);
	free(ip_packet);

	return 0;
}

static void terminate_conn(struct iphdr *ih, struct tcphdr *th)
{
	send_rst(ih->daddr, ih->saddr, th->dest, th->source, th->ack_seq);
	send_rst(ih->saddr, ih->daddr, th->source, th->dest, htonl(ntohl(th->seq)+1));
}

static bool is_allowed(struct sockaddr_in *victim)
{
	unsigned int i;

	for(i = 0; i < num_allowed_ips; i++){
		if(victim->sin_addr.s_addr == allowed_ips[i].s_addr)
			return true;
	}

	return false;
}

static void proc_pkg(char *pkg, ssize_t len)
{
	struct iphdr *ihdr;
	struct tcphdr *thdr;
	struct sockaddr_in src;
	size_t th_offset;

	ihdr = (struct iphdr *)pkg;
	if(ihdr->protocol != IPPROTO_TCP)
		return;

	th_offset = ihdr->ihl*4;
	if(th_offset < len - sizeof(*thdr))
		thdr = (struct tcphdr *)(pkg + th_offset);
	else
		return;

	memset(&src, 0, sizeof(src));
	src.sin_addr.s_addr = ihdr->saddr;

	if(!is_allowed(&src) && !thdr->rst){
		//TODO: add a logging function
		terminate_conn(ihdr, thdr);
	}
}

static void do_firewall()
{
	int enable = 1;
	ssize_t len;
	char pkg_buf[PKGSIZ];

	fd_raw_read = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(fd_raw_read < 0){
		perror("FATAL: socket()");
		exit(1);
	}

	fd_raw_write = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(fd_raw_write < 0){
		perror("FATAL: socket()");
		exit(1);
	}

	if(bind_interface && 
			setsockopt(fd_raw_read, SOL_SOCKET, SO_BINDTODEVICE, bind_interface, strlen(bind_interface)) < 0){

		perror("FATAL: setsockopt()");
		exit(1);
	}

	if(setsockopt(fd_raw_write, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0){
		perror("FATAL: setsockopt()");
		exit(1);
	}

	if(!foreground && daemon(1, 1) != 0){
		perror("FATAL: daemon");
		exit(1);
	}

	for(;;){
		len = recv(fd_raw_read, pkg_buf, sizeof(pkg_buf), 0);
		if(len >= sizeof(struct iphdr) + sizeof(struct tcphdr))
			proc_pkg(pkg_buf, len);
		else if(len == -1){
			perror("FATAL: recv");
			exit(1);
		}
	}
}

static void usage(char *me)
{
	printf("Usage: %s [-f] [-i dev] -a AllowedIP1,AllowedIP2,...,AllowedIPN\n", me);
	printf("Options:\n");
	printf("  -f      : stay in foreground\n");
	printf("  -i DEV  : only filter traffic on interface DEV\n");
	printf("  -a LIST : comma separated list of allowed IPs\n");
	printf("  -h      : show this text\n");

	exit(1);
}

static void setup_allowed_ips(char *iplist)
{
	char *tok;

	num_allowed_ips = 0;

	tok = strtok(iplist, ",");
	while(tok){
		if(num_allowed_ips >= MAX_ALLOWED_IPS){
			printf("FATAL: MAX_ALLOWED_IPS has been reached!\n");
			exit(1);
		}

		if(inet_aton(tok, &allowed_ips[num_allowed_ips++]) == 0){
			printf("FATAL: bad IP address: \"%s\"\n", tok);
			exit(1);
		}

		tok = strtok(NULL, ",");
	}
}

int main(int argc, char **argv)
{
	int opt;

	while((opt = getopt(argc, argv, "hfi:a:")) != -1) {
		switch(opt){
			case 'f':
				foreground = true;
				break;

			case 'i':
				bind_interface = strdup(optarg);
				break;

			case 'a':
				setup_allowed_ips(strdup(optarg));
				break;

			default:
				usage(argv[0]);
		}
	}

	if(!num_allowed_ips)
		usage(argv[0]);

	do_firewall();

	return 0;
}
