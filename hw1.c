#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
	 printf("   Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
         eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

         printf("   Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
         eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));    
    printf("   Protocol: TCP\n");
    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
    printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));
    int tcp_header_len =tcp->tcp_offx2 *4;
    int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int total_packet_len = header->caplen;
    const u_char *payload = packet+ total_header_len;
    int payload_len = total_packet_len - total_header_len;

    	if (payload_len > 0) {
    		printf("   Message (%d bytes): ", payload_len);
    		for (int i = 0; i < payload_len && i < 100; i++) { 
     			if (payload[i]>=32 && payload[i]<=126)
            			printf("%c", payload[i]);
        		else
            			printf(".");
    		}
    		printf("\n");
  	}
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;

}
