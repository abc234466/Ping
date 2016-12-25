#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

typedef char u8;
typedef unsigned short u16;

#define PACKET_SIZE    92
#define IP_OPTION_SIZE 8
#define ICMP_PACKET_SIZE   PACKET_SIZE - (int)sizeof(struct ip) - IP_OPTION_SIZE
#define ICMP_DATA_SIZE     ICMP_PACKET_SIZE - (int)sizeof(struct icmphdr)
//default send count 3 
#define DEFAULT_SEND_COUNT 3
//default timeout 2000ms
#define DEFAULT_TIMEOUT 2000

//set device 
static const char *dev = "eth0";
//static const char *dev = "ens33";

typedef struct
{
	struct ip ip_hdr;
	u8 ip_option[8];
	struct icmphdr icmp_hdr;
	u8 data[0];
} myicmp ;

void 
fill_iphdr ( myicmp *mi , const char* dst_ip, char *gateway);

void
fill_icmphdr ( myicmp *ir, u16 seq_num);

u16
fill_cksum(unsigned short *addr,unsigned int len);
 
#endif
 
