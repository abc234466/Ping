#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

extern int seq_num;	//sequence number for checking reply
extern int timeout;

extern pid_t pid;
extern u16 icmp_req;

static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p;
static struct pcap_pkthdr hdr;

/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */
void pcap_init( const char* dst_ip ,int timeout, int pid )
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct in_addr addr;
	struct bpf_program fcode;
	
	bpf_u_int32 maskp;	
	bpf_u_int32 netp;

	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

	if(ret == -1){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	addr.s_addr = netp;

	net = inet_ntoa(addr);	
	if(net == NULL){
		perror("net - inet_ntoa error");
		exit(1);
	}
	
	addr.s_addr = maskp;

	mask = inet_ntoa(addr);
	if(mask == NULL){
		perror("mask - inet_ntoa error");
		exit(1);
	}
	
	p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	/*
	 *    you should complete your filter string before pcap_compile
	 *    Reference: http://www.manpagez.com/man/7/pcap-filter/
	 */
	
	sprintf(filter_string,"host %s and icmp[icmptype] == icmp-echoreply",dst_ip);

	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}

int pcap_get_reply( void )
{

	const u_char *ptr;
	
	/*
	 * google "pcap_next" to get more information
	 * and check the packet that ptr pointed to.
	 */
	while(ptr = pcap_next(p, &hdr))
	{
		
		myicmp *reply = (myicmp*)malloc(PACKET_SIZE);
		int i;
		double rtt = hdr.ts.tv_usec/10e6;
	    
	    char temp[PACKET_SIZE];
	    for(i=0;i<PACKET_SIZE;i++)
	    {
	        temp[i] = ptr[i+14];
	    }
		
	    memcpy(reply, &temp, PACKET_SIZE);
	    
		printf("Reply from %s: time = %.3lfms\n", inet_ntoa(reply->ip_hdr.ip_src), rtt);
		
        return 0;
    }
    return -1;
}

//Print usage 
void Print_Format()
{
	printf("Fomat Error!\nUsage: sudo ./myping -g gateway [-w timeout (in msec)] [-c count] target_ip\n");
	exit(1);
}

//process command
void proccmd(char *argv[], char **tp, int *count, int *to, char **gateway)
{
	for(argv+=1 ; *argv !=NULL; argv++)
	{
		//check gateway
		if(strcmp(*argv, "-g") == 0 )
		{
			argv +=1;
			if(*argv !=NULL && inet_addr(*argv) !=1)
				*gateway = *argv;
			else
				Print_Format();
		}
		//check timeout
		else if(strcmp(*argv, "-w") ==0)
		{
			argv +=1;
			if(*argv !=NULL)
				sscanf(*argv, "%d", to);
			else
				Print_Format();
		}
		//check count
		else if(strcmp(*argv, "-c")==0)
		{
			argv +=1;
			if(*argv !=NULL)
				sscanf(*argv, "%d", count);
			else
				Print_Format();
		}
		//check target_ip	
		else if(inet_addr(*argv) !=-1)
			*tp = *argv;
		else
			Print_Format();
	}
	if(*tp == NULL)
		Print_Format();
}
