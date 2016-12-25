#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern int seq_num; //sequence number for checking reply
extern pid_t pid;

void fill_iphdr ( myicmp *mi , const char* dst_ip, char *gateway)
{
	
	struct ifreq freq;
    freq.ifr_addr.sa_family = AF_INET;
    strncpy(freq.ifr_name, dev, IFNAMSIZ-1);
    
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ioctl(fd, SIOCGIFADDR, &freq);
    
    struct in_addr gaddr;
    gaddr.s_addr = inet_addr(gateway);
    // src IP address
    char * src; 

	struct ip *ip_hdr = &mi->ip_hdr;
		
	//fill IP header
	//reference -> http://minirighi.sourceforge.net/html/structip.html#_details
	//IP version
	ip_hdr->ip_v = 4;
	
	// IP header length
    ip_hdr->ip_hl = 7; 
    
    //type of service
    ip_hdr->ip_tos = 0;
    
    //Total length = 92 
    ip_hdr->ip_len = 92; 
    
    //identification
    ip_hdr->ip_id = 0; 
    
    //time to live			
    ip_hdr->ip_ttl = 64; 
    
	//Fragment offset
    ip_hdr->ip_off = htons(0x4000);
    
    //protocol ->ICMP
    ip_hdr->ip_p = IPPROTO_ICMP; 

	
    src = inet_ntoa(((struct sockaddr_in *)&freq.ifr_addr)->sin_addr);

	// src IP
    inet_aton(src, &(ip_hdr->ip_src));
    // dst IP
    inet_aton(dst_ip, &(ip_hdr->ip_dst));
	
	//Loose Source Route
	mi->ip_option[0] = 0x83;
	//Record Route	
    mi->ip_option[1] = 7;	
    mi->ip_option[2] = 4;
    //gateway
    memcpy(&mi->ip_option[3], &gaddr, sizeof(struct in_addr));
	
    close(fd);
}

void fill_icmphdr ( myicmp *ir, u16 seq_num)
{
	int i;
	struct icmphdr *icmp_hdr =&ir->icmp_hdr;
	//process ICMP header
	//reference->https://www.cymru.com/Documents/ip_icmp.h
	//type
	icmp_hdr -> type = ICMP_ECHO;
	
	// process id
    icmp_hdr -> un.echo.id = pid; 
    
    //code
    icmp_hdr -> code = htons(0);
    
    //seq number
    icmp_hdr ->un.echo.sequence = htons(seq_num);
    
    // fill data
    for( i = 0 ; i < ICMP_DATA_SIZE ; i++)
    {
	    ir -> data[i] = (rand() & 0xFF);
    }
    
    //ICMP cksum
	icmp_hdr->checksum = 0;    
	icmp_hdr->checksum = fill_cksum((unsigned short *)icmp_hdr, ICMP_PACKET_SIZE);
}

//chksm
u16 fill_cksum(unsigned short *addr,unsigned int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
	
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	
	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}
