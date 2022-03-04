// Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
// 
// Sending ICMP Echo Requests using Raw-sockets.
//

#include <stdio.h>
//  linux

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#include <time.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>


 // IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);

// 1. Change SOURCE_IP and DESTINATION_IP to the relevant
//     for your computer
// 2. Compile it using MSVC compiler or g++
// 3. Run it from the account with administrative permissions,
//    since opening of a raw-socket requires elevated preveledges.
//
//    On Windows, right click the exe and select "Run as administrator"
//    On Linux, run it as a root or with sudo.
//
// 4. For debugging and development, run MS Visual Studio (MSVS) as admin by
//    right-clicking at the icon of MSVS and selecting from the right-click 
//    menu "Run as administrator"
//
//  Note. You can place another IP-source address that does not belong to your
//  computer (IP-spoofing), i.e. just another IP from your subnet, and the ICMP
//  still be sent, but do not expect to see ICMP_ECHO_REPLY in most such cases
//  since anti-spoofing is wide-spread.

#define SOURCE_IP "127.0.0.1"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "8.8.8.8"

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

int got_packet(const u_char *packet)
{
    int ip_header_len;
    // struct ethheader *eth = (struct ethheader *)packet;//point to the beggining of the ethernet header

    // if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader * ip = (struct ipheader *)(packet);  //point to the beggining of the ip header

        /* determine protocol */
        if(ip->iph_protocol == IPPROTO_ICMP) {                                
            ip_header_len = ip->iph_ihl * 4;
            struct icmp * icmp = (struct icmp*)(packet + ip_header_len);//point to the beggining of the ICMP header
            if(icmp->icmp_id == 18){
                return 1;
            }
        }
    // }
    return 0;
}

int main ()
{
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping.\n";

    int datalen = strlen(data) + 1;

    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = 8;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet 
    char packet[IP_MAXPACKET];

    // ICMP header
    memcpy ((packet ), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy (packet  + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet ), ICMP_HDRLEN + datalen);
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    // The port is irrelant for Networking and therefore was zeroed.
    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);

    // Create raw socket for ICMP-RAW 
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    // This socket option IP_HDRINCL says that we are building IPv4 header by ourselves, and
    // the networking in kernel is in charge only for Ethernet header.
    //
    const int flagOne = 1;
    int PACKET_LEN = 512;
    char buffer[PACKET_LEN];
    struct sockaddr saddr;
    clock_t begin = clock();
    struct timeval before, after;
    gettimeofday(&before, NULL);

    // Send the packet using sendto() for sending datagrams.
    if (sendto (sock, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  
    {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    while (1) {
        int data_size=recvfrom(sock, buffer, PACKET_LEN, 0,  &saddr, (socklen_t*)sizeof(saddr));
        if(data_size && got_packet((u_char*)buffer)) {
          break;
        }
    }
    clock_t end = clock();
    gettimeofday(&after,NULL);
    double totalMil = ((double)(after.tv_usec-before.tv_usec))/1000;
    double totalMic = (double)(after.tv_usec-before.tv_usec);

    printf("time in milliseconds: %lf, time in microseconds: %lf", totalMil, totalMic);
  // Close the raw socket descriptor.
  close(sock);

  return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}
