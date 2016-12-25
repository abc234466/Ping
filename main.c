#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "fill_packet.h"
#include "pcap.h"
#include <time.h>

//getuid
#include <unistd.h>
#include <sys/types.h>

pid_t pid;
//ICMP seq num	
int seq_num;

int main(int argc, char* argv[])
{
	int sockfd, on=1;
	
	
	//ICMP packet.
	myicmp *packet = (myicmp*)malloc(PACKET_SIZE);	
	struct sockaddr_in dst;
	int timeout = DEFAULT_TIMEOUT;
	int count = DEFAULT_SEND_COUNT;
    char *gateway = NULL,*target_ip=NULL;
	
	pid = getpid();
	
	//process command
	uid_t uid = getuid();
	//root or not
	if(uid!=0)
	{
		puts("ERROR: You must be root to use this tool!");
	}
	else
	{
		proccmd(argv, &target_ip, &count, &timeout, &gateway);
	}
	
	//printf("ok\n");
	
	/* 
	 * in pcap.c, initialize the pcap
	 */
	pcap_init(target_ip , timeout, pid);//	target_ip,timeout
	
	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0){
		perror("sockfd - socket error");
		exit(1);
	}

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
		perror("sockfd - setsockopt error");
		exit(1);
	}
	
	// fill dst
	bzero(&dst, sizeof(dst));	
	dst.sin_family = AF_INET;
	dst.sin_port = htons(44320);
	dst.sin_addr.s_addr = inet_addr(target_ip);
	
	
	//ping information
	printf("Ping %s ( data size = %d, id = 0x%x, timeout = %d, count = %d):\n", 
		target_ip, ICMP_DATA_SIZE, htons(pid), timeout, count);
	
	

	//printf("%s",target_ip);
	for(seq_num=1; seq_num<=count; seq_num++)
	{
	 	
	 	
		//fill IP header
		fill_iphdr(packet, target_ip, gateway);
		
        //printf("%s",gateway);

	    //fill ICMP header
        fill_icmphdr(packet, seq_num);
		
		/*
	 	 *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
 		 *   to get the "ICMP echo response" packets.
		 *	 You should reset the timer every time before you send a packet.
	 	 */
	    if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0){
            perror("sockfd - sendto error");
		    exit(1);
	    }
	    
		if(pcap_get_reply() ==-1)
			printf("Reply from %s: time = *\n", target_ip);
		else
			printf("\tRouter: %s\n", gateway);
	}

	free(packet);
	return 0;
}



