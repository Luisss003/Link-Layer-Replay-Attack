#include <stdio.h>
#include <pcap.h>
#include <dumbnet.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "file_info.h"
#include "packet_reading.h"
#include <unistd.h>
#include <string.h>
#include "pkt_trans.h"
#include "packet_sniffing.h"
#include <netinet/tcp.h>

//JUST READS CONFIG FILE AND OPENS PCAP FILE
int read_cfg_file(char *cgf_file){
  int pcap_fd;
  FILE *cfg_fp;
  char pcap_file_name[100];

  cfg_fp = fopen(cgf_file, "r");
  if (cfg_fp == NULL){
    printf("Error opening config file\n");
    return -1;
  }
  
  fgets(pcap_file_name, sizeof(pcap_file_name), cfg_fp);
  pcap_file_name[strcspn(pcap_file_name, "\n")] = 0;
  pcap_fd = open(pcap_file_name, O_RDONLY);
  
  if (pcap_fd < 0){
    printf("Error opening pcap file\n");
    fclose(cfg_fp);
    return -1;
  }

  //Parse PCAP global header
  read_pcap_global_header(pcap_fd);
  
  //Read PCAP file, and create packet based on parameters
  create_att_pkt(pcap_fd, cfg_fp);
  return 0;  
}


void read_pcap_global_header(int pcap_fd){
  struct pcap_file_header pcaphdr;
  read(pcap_fd, &pcaphdr, sizeof(pcaphdr));

  switch (pcaphdr.magic){

    case PCAP_MAGIC:
      printf("PCAP_MAGIC\n");
      break;
    case PCAP_SWAPPED_MAGIC:
      printf("PCAP_SWAPPED_MAGIC\n");
      break;
    case PCAP_MODIFIED_MAGIC:   
      printf("PCAP_MODIFIED_MAGIC\n");
      break;
    case PCAP_SWAPPED_MODIFIED_MAGIC:
      printf("PCAP_SWAPPED_MODIFIED_MAGIC\n");
      break;
    default:
      printf("Unknown magic number\n");
      break;
  }

  printf("Version major number = %u\n", pcaphdr.version_major);
  printf("Version minor number = %u\n", pcaphdr.version_minor);
  printf("GMT to local correction = %u\n", pcaphdr.thiszone);
  printf("Timestamp accuracy = %u\n", pcaphdr.sigfigs);
  printf("Snaplen = %u\n", pcaphdr.snaplen);
  printf("Linktype = %u\n", pcaphdr.linktype);
  
}

void create_att_pkt(int pcap_fd, FILE *cfg_fp){
  struct my_pkthdr pkthdr;
  unsigned char packet_buffer[65535];
  unsigned int pkt_count = 0;
  struct eth_hdr *ethhdr;
  int firsttime = 1;
  int b_usec, c_usec;
  unsigned int b_sec, c_sec;
  struct config_data cfg_info;
  cfg_info = read_cfg(cfg_fp);


  //Initialize ethernet interface for ethernet and sniffer
  if(init_eth(cfg_info.interface) < 0){
    printf("Error initializing ethernet interface\n");
    return;
  }	
  if(init_sniffer(cfg_info.interface) < 0){
    printf("Error initializaing sniffer\n");
	return;
  }

  //While there are packets in pcap file
  while(read(pcap_fd, &pkthdr, sizeof(pkthdr)) != 0){
    //Print timing on each packet
    if(firsttime){
      firsttime = 0;
      b_sec = pkthdr.ts.tv_sec;
      b_usec = pkthdr.ts.tv_usec;
    }
    c_sec = pkthdr.ts.tv_sec - b_sec;
    c_usec = pkthdr.ts.tv_usec - b_usec;

    while (c_usec < 0){
      c_sec--;
      c_usec += 1000000;
    }

    //Print packet length and time info
    printf("\nPacket %u\n", pkt_count);
    printf("%u.%06u\n", (unsigned)c_sec, (unsigned)c_usec);
    pkt_count++; 
    printf("Captured Packet Length = %d\n", pkthdr.caplen);
    printf("Actual Packet Length = %d\n",pkthdr.len);
  

	//Read entire packet
    read(pcap_fd, packet_buffer,pkthdr.len);

	//Create ptr to ethernet header in packet buffer
    ethhdr = (struct eth_hdr *)packet_buffer;
    printf("Ethernet Header\n");

	//Check to see if ethernet MAC of current packet matches attacker IP
	//If so, replace with our own MAC
	//Prepares packet for sending
    if(memcmp(&ethhdr->eth_src, &cfg_info.attacker_mac, sizeof(eth_addr_t)) == 0){
      printf("   src_mac = %s\n", eth_ntoa(&ethhdr->eth_src));
      printf("   dst_mac = %s\n", eth_ntoa(&cfg_info.replay_victim_mac));
      ethhdr->eth_src = cfg_info.replay_attacker_mac;
      ethhdr->eth_dst = cfg_info.replay_victim_mac;
      printf("   rep_src_mac = %s\n", eth_ntoa(&ethhdr->eth_src));
      printf("   rep_dst_mac = %s\n", eth_ntoa(&ethhdr->eth_dst));
    
    }
	//If not, just print the packet information and data as is
    else{
      printf("   src_mac = %s\n", eth_ntoa(&ethhdr->eth_src));
      printf("   dst_mac = %s\n", eth_ntoa(&ethhdr->eth_dst));
    }

	  //Check whether packet is IP packet or ARP (link layer only)
      switch(ntohs(ethhdr->eth_type)){
        case ETH_TYPE_IP:  
          read_ip(packet_buffer, &cfg_info);
          break;
        case ETH_TYPE_ARP:
          read_arp(packet_buffer);
          break;
        default:
          printf("   OTHER\n");
          break;
      }

  }
	close_sniffer();
}

void read_ip(unsigned char *packet_buffer, struct config_data *cfg_info){
  struct ip_hdr *iphdr;

  //Create ptr to IP header in packet buffer
  //+ETH_HDR_LEN to skip those bytes, and end on ethernet header
  iphdr = (struct ip_hdr *)(packet_buffer + ETH_HDR_LEN);

  //Print IP packet length + IP addresses
  printf("   IP\n");
  printf("      ip_len = %u\n", ntohs(iphdr->ip_len));

  //Print the source and destination IP addresses
  uint8_t *ip_bytes = (uint8_t *)&iphdr->ip_src;
  printf("      ip_src = %u.%u.%u.%u\n",
         ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

  uint8_t *dst_bytes = (uint8_t *)&iphdr->ip_dst;
  printf("      ip_dst = %u.%u.%u.%u\n",
         dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3]);

  //Check if the source IP address matches attacker IP
  //if so, switch with our IP adddress
  if (memcmp(&iphdr->ip_src, &cfg_info->attacker_ip, sizeof(ip_addr_t)) == 0) {
      //Replace source and dst IP with mine, and the victim machines IP
      memcpy(&iphdr->ip_src, &cfg_info->replay_attacker_ip, sizeof(ip_addr_t));
      memcpy(&iphdr->ip_dst, &cfg_info->replay_victim_ip, sizeof(ip_addr_t));

	  //Print new IP addresses
      ip_bytes = (uint8_t *)&iphdr->ip_src;
      printf("      rep_src = %u.%u.%u.%u\n",
             ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

      dst_bytes = (uint8_t *)&iphdr->ip_dst;
      printf("      rep_dst = %u.%u.%u.%u\n",
             dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3]);
  }

  //Calculate true header size of IP packet
  unsigned int true_hdr_size = iphdr->ip_hl * 4;

  //Check to see what kind of packet encapsulated within IP packet
  switch (iphdr->ip_p) {
      case IP_PROTO_TCP:
          read_tcp(true_hdr_size, packet_buffer, cfg_info);
          break;
      case IP_PROTO_UDP:
          read_udp(true_hdr_size, packet_buffer);
          break;
      case IP_PROTO_ICMP:
          read_icmp(true_hdr_size, packet_buffer);
          break;
      case IP_PROTO_IGMP:
          printf("      IGMP\n");
          break;
      default:
          printf("      OTHER\n");
          break;
  }
}

void read_arp(unsigned char *packet_buffer){
  struct arp_hdr *arphdr;
  printf("   ARP\n");
  
  arphdr = (struct arp_hdr *)(packet_buffer + ETH_HDR_LEN);
  
  switch(ntohs(arphdr->ar_op)){
    case ARP_OP_REQUEST:
      printf("      Request");
      break;
    case ARP_OP_REPLY:
      printf("      Reply"); 
      break;
    case ARP_OP_REVREQUEST:
      printf("      Reverse Request");
      break;
    case ARP_OP_REVREPLY:
      printf("      Reverse Reply");
      break;
    default:
      printf("      Unknown");
   
  }
}

void read_tcp(unsigned int true_hdr_size, unsigned char *packet_buffer, struct config_data *cfg_info) {
    struct tcp_hdr *tcphdr;
	
	//Create TCP header ptr in packet buffer
	//+ ETH + true IP hdr size to skip those bytes and land on TCP hdr.
    tcphdr = (struct tcp_hdr *)(packet_buffer + ETH_HDR_LEN + true_hdr_size);
    printf("      TCP\n");

	//Point to the src and dst ports on TCP header
    uint16_t src_port = ntohs(tcphdr->th_sport);
    uint16_t dst_port = ntohs(tcphdr->th_dport);

	//Print TCP port and syn/ack #s of current unaltered packet
    printf("         src_port = %u\n", src_port);
    printf("         dst_port = %u\n", dst_port);
    printf("         seq = %u\n", ntohl(tcphdr->th_seq));
    printf("         ack = %u\n", ntohl(tcphdr->th_ack));

	//IF the src port of current packet matches the port of the attacker, and the dst port matches
	
	//victims port, then switch out the ports for mine and the victims in the packet
    if (src_port == cfg_info->attacker_port && dst_port == cfg_info->victim_port) {
        tcphdr->th_sport = htons(cfg_info->replay_attacker_port);
        tcphdr->th_dport = htons(cfg_info->replay_victim_port);

        // Update ACK number to track victim sequence
        tcphdr->th_ack = htonl(latest_victim_seq);
        

        printf("         rep_src_port = %u\n", ntohs(tcphdr->th_sport));
        printf("         rep_dst_port = %u\n", ntohs(tcphdr->th_dport));
        printf("         new ack = %u\n", latest_victim_seq + 1);

        struct ip_hdr *iphdr = (struct ip_hdr *)(packet_buffer + ETH_HDR_LEN);
        ip_checksum(iphdr, ntohs(iphdr->ip_len));

	//If the timing is delay, 
	if (strcmp(cfg_info->timing, "delay") == 0) {
   		struct pcap_pkthdr hdr;

		//Sniff victim response packets
   		receive_victim_packet(cfg_info, &hdr);

		//Imeplement delay for pacing
   		usleep(500000);  // Optional small pacing delay
	}

	//If the latest packet seq is not zero, update the attackers ACK
  if (latest_victim_seq != 0) {
    tcphdr->th_ack = htonl(latest_victim_seq);
    printf("         updated ack = %u\n", latest_victim_seq);
  }

  //Recalculate packet checksum after altering ACK #
  ip_checksum(iphdr, ntohs(iphdr->ip_len));

  if (send_modified_packet(packet_buffer, ntohs(iphdr->ip_len) + ETH_HDR_LEN, cfg_info) == 0) {
    printf("   Packet sent\n");
  }	
	}
}

void read_udp(unsigned int true_hdr_size, unsigned char *packet_buffer){
  struct udp_hdr *udphdr;
  udphdr = (struct udp_hdr *)(packet_buffer + ETH_HDR_LEN + true_hdr_size);
  printf("      UDP\n");
  printf("         src_port = %u\n", (unsigned short)ntohs(udphdr->uh_sport));
  printf("         dst_port = %u", (unsigned short)ntohs(udphdr->uh_dport));
}

void read_icmp(unsigned int true_hdr_size, unsigned char *packet_buffer){
  struct icmp_hdr *icmphdr;
  icmphdr = (struct icmp_hdr *)(packet_buffer + ETH_HDR_LEN + true_hdr_size);
  printf("      ICMP\n");
  switch(icmphdr->icmp_type) {
    case ICMP_ECHOREPLY:
          printf("         Echo Reply");
          break;
        case ICMP_UNREACH:
          printf("         Destination Unreachable");
          break;
        case ICMP_SRCQUENCH:
          printf("         Source Quench");
          break;
        case ICMP_REDIRECT:
          printf("         Redirect");
          break;
        case ICMP_ALTHOSTADDR:
          printf("         Alternate Host Address");
          break;
        case ICMP_ECHO:
          printf("         Echo");
          break;
        case ICMP_RTRADVERT:
          printf("         Router Advertisement");
          break;
        case ICMP_RTRSOLICIT:
          printf("         Router Solicitation");
          break;
        case ICMP_TIMEXCEED:
          printf("         Time Exceeded");
          break;
        case ICMP_PARAMPROB:
          printf("         Parameter Problem");
          break;
        case ICMP_TSTAMP:
          printf("         Timestamp Request");
          break;
        case ICMP_TSTAMPREPLY:
          printf("         Timestamp Reply");
          break;
        case ICMP_INFO:
          printf("         Information Request");
          break;
        case ICMP_INFOREPLY:
          printf("         Information Reply");
          break;
        case ICMP_MASK:
          printf("         Address Mask Request");
          break;
        case ICMP_MASKREPLY:
          printf("         Address Mask Reply");
          break;
        case ICMP_TRACEROUTE:
          printf("         Traceroute");
          break;
        case ICMP_DATACONVERR:
          printf("         Datagram Conversion Error");
          break;
        case ICMP_MOBILE_REDIRECT:
          printf("         Mobile Host Redirect");
          break;
        case ICMP_IPV6_WHEREAREYOU:
          printf("         IPv6 Where-Are-You");
        break;
        case ICMP_IPV6_IAMHERE:
          printf("         IPv6 I-Am-Here");
          break;
        case ICMP_MOBILE_REG:
          printf("         Mobile Registration Request");
          break;
        case ICMP_MOBILE_REGREPLY:
          printf("         Mobile Registration Reply");
          break;
        case ICMP_DNS:  
          printf("         Domain Name Request");
          break;
        case ICMP_DNSREPLY:
          printf("         Domain Name Reply");
          break;
        case ICMP_SKIP:
          printf("         SKIP");
          break;
        case ICMP_PHOTURIS:
          printf("         Photuris");
          break;
        default: 
          printf("         ERROR");
          break;
  }
}
