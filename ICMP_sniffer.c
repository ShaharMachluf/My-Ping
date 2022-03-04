#include <pcap/pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct sniff_icmp{
	#define ICMP_ECHO_REQ 8
	#define ICMP_ECHO_RES 0
	#define ICMP_HDR_LEN 4
 	unsigned char icmp_type;
 	unsigned char icmp_code;
 	unsigned short icmp_cksum;						
};

struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

void got_packet(const u_char *packet)
{
  int ip_header_len;
  struct ethheader *eth = (struct ethheader *)packet;//point to the beggining of the ethernet header

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));  //point to the beggining of the ip header

    /* determine protocol */
    if(ip->iph_protocol == IPPROTO_ICMP) {    
      printf("From: %s\n", inet_ntoa(ip->iph_sourceip));  
      printf("To: %s\n", inet_ntoa(ip->iph_destip));                             
      ip_header_len = ip->iph_ihl * 4;
      struct sniff_icmp * icmp = (struct sniff_icmp*)(packet + sizeof(struct ethheader) + ip_header_len);//point to the beggining of the ICMP header
      printf("icmp type: %d\n", icmp->icmp_type);
      printf("icmp code: %d\n", icmp->icmp_code);
    }
  }
}


int main() {
    int PACKET_LEN = 512;
    char buffer[PACKET_LEN];
    struct sockaddr saddr;
    struct packet_mreq mr;

    // Create the raw socket
    int sock = socket(AF_PACKET, SOCK_RAW,  htons(ETH_P_ALL));  

    // Turn on the promiscuous mode. 
    mr.mr_type = PACKET_MR_PROMISC;                           
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,  
                     sizeof(mr));

    // Getting captured packets
    while (1) {
        int data_size=recvfrom(sock, buffer, PACKET_LEN, 0,  
	                 &saddr, (socklen_t*)sizeof(saddr));
        if(data_size) {
          got_packet(buffer);
        }
    }

    close(sock);
    return 0;
}