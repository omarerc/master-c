/** Author: Omar Ramirez           */
/** My Cyber Joy - Project         */
/** Network Traffic Sniffer        */

/** Standard Libraries */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
/** LLVM Library */
#include <signal.h>
/** Linux Kernel */
#include <linux/if_packet.h>
/** Networking */
#include<arpa/inet.h>
#include<netinet/in.h>		 
#include<netinet/if_ether.h> 
#include<netinet/ip.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
/** Unix BSD */
#include <unistd.h>

FILE* packetLog;
int count, tcp, udp, icmp, other, iphdrlen;
struct sockaddr sckaddr;
struct sockaddr_in src, dst;

/** Network TCP Stack Layers */
/** Ethernet Layer 2 */
void ethernet_header(unsigned char* buffer,int buflen)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	fprintf(packetLog, 
    "\nEthernet Header\n");
	fprintf(packetLog, 
    "\t|-Source Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
      eth->h_source[0],
      eth->h_source[1],
      eth->h_source[2],
      eth->h_source[3],
      eth->h_source[4],
      eth->h_source[5]);
	fprintf(packetLog, 
    "\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
      eth->h_dest[0],
      eth->h_dest[1],
      eth->h_dest[2],
      eth->h_dest[3],
      eth->h_dest[4],
      eth->h_dest[5]);
	fprintf(packetLog, 
    "\t|-Protocol		: %d\n",
      eth->h_proto);
}

/** IP Layer 3 */
void ip_header(unsigned char* buffer,int buflen)
{
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	iphdrlen =ip->ihl*4;

	memset(&src, 0, sizeof(src));
	src.sin_addr.s_addr = ip->saddr;     
	memset(&dst, 0, sizeof(dst));
	dst.sin_addr.s_addr = ip->daddr;     

	fprintf(packetLog , "\nIP Header\n");
	fprintf(packetLog,
    "\t|-Version              : %d\n",
    (unsigned int)ip->version);
	fprintf(packetLog,
    "\t|-Internet Header Length  : %d DWORDS or %d Bytes\n",
    (unsigned int)ip->ihl,
    ((unsigned int)(ip->ihl))*4);
	fprintf(packetLog,
    "\t|-Type Of Service   : %d\n",
    (unsigned int)ip->tos);
	fprintf(packetLog,
    "\t|-Total Length      : %d  Bytes\n",
    ntohs(ip->tot_len));
	fprintf(packetLog,
    "\t|-Identification    : %d\n",
    ntohs(ip->id));
	fprintf(packetLog,
    "\t|-Time To Live	    : %d\n",
    (unsigned int)ip->ttl);
	fprintf(packetLog,
    "\t|-Protocol 	    : %d\n",
    (unsigned int)ip->protocol);
	fprintf(packetLog,
    "\t|-Header Checksum   : %d\n",
    ntohs(ip->check));
	fprintf(packetLog,
    "\t|-Source IP         : %s\n",
    inet_ntoa(src.sin_addr));
	fprintf(packetLog,
    "\t|-Destination IP    : %s\n",
    inet_ntoa(dst.sin_addr));
}

/** Application Layer 4 */
void payload(unsigned char* buffer, int buflen)
{
	int i=0;
	unsigned char * data = (buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	fprintf(packetLog,"\nData\n");
	int remaining_data = buflen - (iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	for(i=0; i<remaining_data; i++)
	{
		if(i!=0 && i%16==0)
			fprintf(packetLog,
        "\n");
		fprintf(packetLog,
      " %.2X ",
      data[i]);
	}

	fprintf(packetLog,"\n");
}

void tcp_header(unsigned char* buffer,int buflen)
{
	fprintf(packetLog,"\n*************************TCP Packet******************************");
  ethernet_header(buffer,buflen);
  ip_header(buffer,buflen);

  struct tcphdr *tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
  fprintf(packetLog,
    "\nTCP Header\n");
  fprintf(packetLog, "\t|-Source Port          : %u\n",
    ntohs(tcp->source));
  fprintf(packetLog, "\t|-Destination Port     : %u\n",
    ntohs(tcp->dest));
  fprintf(packetLog, "\t|-Sequence Number      : %u\n",
    ntohl(tcp->seq));
  fprintf(packetLog, "\t|-Acknowledge Number   : %u\n",
    ntohl(tcp->ack_seq));
  fprintf(packetLog, "\t|-Header Length        : %d DWORDS or %d BYTES\n" ,
    (unsigned int)tcp->doff,(unsigned int)tcp->doff*4);
  fprintf(packetLog,
    "\t|----------Flags-----------\n");
  fprintf(packetLog,
    "\t\t|-Urgent Flag          : %d\n",(unsigned int)tcp->urg);
  fprintf(packetLog,
    "\t\t|-Acknowledgement Flag : %d\n",(unsigned int)tcp->ack);
  fprintf(packetLog,
    "\t\t|-Push Flag            : %d\n",(unsigned int)tcp->psh);
  fprintf(packetLog, "\t\t|-Reset Flag           : %d\n",
    (unsigned int)tcp->rst);
  fprintf(packetLog, "\t\t|-Synchronise Flag     : %d\n",
    (unsigned int)tcp->syn);
  fprintf(packetLog, "\t\t|-Finish Flag          : %d\n",
    (unsigned int)tcp->fin);
  fprintf(packetLog, "\t|-Window size          : %d\n",
    ntohs(tcp->window));
  fprintf(packetLog, "\t|-Checksum             : %d\n",
    ntohs(tcp->check));
  fprintf(packetLog, "\t|-Urgent Pointer       : %d\n",
    tcp->urg_ptr);
  payload(buffer,buflen);
  fprintf(packetLog,
    "*****************************************************************\n\n\n");
}

void udp_header(unsigned char* buffer, int buflen)
{
	fprintf(packetLog,"\n*************************UDP Packet******************************");
	ethernet_header(buffer,buflen);
	ip_header(buffer,buflen);
	fprintf(packetLog,"\nUDP Header\n");
	struct udphdr *udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	fprintf(packetLog,
    "\t|-Source Port    	: %d\n" ,
    ntohs(udp->source));
	fprintf(packetLog,
    "\t|-Destination Port	: %d\n" ,
    ntohs(udp->dest));
	fprintf(packetLog, "\t|-UDP Length      	: %d\n",
    ntohs(udp->len));
	fprintf(packetLog, "\t|-UDP Checksum   	: %d\n" ,
    ntohs(udp->check));
	payload(buffer,buflen);
	fprintf(packetLog,
    "*****************************************************************\n\n\n");
}

void data_process(unsigned char* buffer,int buflen)
{
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof (struct ethhdr));
	++count;
	/* we will se UDP Protocol only*/ 
	switch (ip->protocol)    //see /etc/protocols file 
	{
		case 6:
			++tcp;
			tcp_header(buffer,buflen);
			break;
		case 17:
			++udp;
			udp_header(buffer,buflen);
			break;
		default:
			++other;
	}
	printf("TCP: %d  UDP: %d  Other: %d  Toatl: %d  \r",
    tcp,
    udp,
    other,
    count);
}



int main()
{
	int sock_r,saddr_len,buflen;

	unsigned char* buffer = (unsigned char *)malloc(65536); 
	memset(buffer,0,65536);

	packetLog=fopen("log.txt","w");
	if(!packetLog)
	{
		printf("Error: unable to open log.txt file.\n");
		return -1;

	}

	printf("Starting Sniff Process.... \n");

	sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); 
	if(sock_r<0)
	{
		printf("Error to connect Raw Socket.\n");
		return -1;
	}

	while(1)
	{
		saddr_len = sizeof sckaddr;
		buflen = recvfrom(sock_r,buffer, 65536, 0, &sckaddr, (socklen_t *)&saddr_len);


		if(buflen<0)
		{
			printf("error in reading recvfrom function\n");
			return -1;
		}
		fflush(packetLog);
		data_process(buffer, buflen);

	}

	close(sock_r);// use signals to close socket 
	printf("Ending Sniff Process.\n");

}