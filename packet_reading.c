#include <stdio.h>
#include <pcap.h>
#include <dumbnet.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "file_info.h"
#include "packet_reading.h"
#include <unistd.h>

int parse_pcap(char *cfg_file_name){
  int pcap_fd;
  FILE *cfg_fp;
  char pcap_file_name[50];

  //Open the configuration file and read to pcap name buffer
  cfg_fp = fopen(cfg_file_name, "r");
  fgets(pcap_file_name, 50, cfg_fp);
  
  //Use that pcap file name to create file descriptor
  pcap_fd = open(pcap_file_name, O_RDONLY);
  //Read/print header info for pcap
  read_pcap_global_header(pcap_fd);
  
  create_attack_packets(pcap_fd, cfg_fp);

  close(pcap_fd);
  fclose(cfg_fp);
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
  printf("Linktype = %u", pcaphdr.linktype);
  
}
void create_attack_packets(int pcap_fd, FILE *cfg_fp){
  struct my_pkthdr pkthdr;
  unsigned char packet_buffer[65535];
  unsigned int pkt_count = 0;
  struct eth_hdr *ethhdr;
  struct config_data cfg_info;
  int firsttime = 1;
  int b_usec, c_usec;
  unsigned int b_sec, c_sec;

  //Read and set struct for config data
  cfg_info = read_cfg(cfg_fp);

  while(read(pcap_fd, &pkthdr, sizeof(pkthdr)) != 0){
 
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

    printf("\n\nPacket %u\n", pkt_count);
    printf("%u.%06u\n", (unsigned)c_sec, (unsigned)c_usec);
    pkt_count++; 
    printf("Captured Packet Length = %d\n", pkthdr.caplen);
    printf("Actual Packet Length = %d\n",pkthdr.len);
  
    //Second read for packet itself
    read(pcap_fd, packet_buffer,pkthdr.len);

    //Read ethernet header 
    ethhdr = (struct eth_hdr *)packet_buffer;
    printf("Ethernet Header\n");
    
    //If packet has src MAC of attacker, addresses to replay
    if(addr_cmp(&ethhdr->eth_src, &cfg_info.attacker_mac) == 0){
      printf("   src_mac = %s\n", addr_ntoa(&ethhdr->eth_src));
      printf("   dst_mac = %s\n", addr_ntoa(&cfg_info.replay_victim_mac));
      printf("   eth_type = %u\n", ntohs(ethhdr->eth_type));
      ethhdr->eth_src = cfg_info.replay_attacker_mac;
      ethhdr->eth_dst = cfg_info.replay_victim_mac;
      printf("   rep_src_mac = %s\n", addr_ntoa(&ethhdr->eth_src));
      printf("   rep_dst_mac = %s\n", addr_ntoa(&ethhdr->eth_dst));
      printf("   REPLAYING PACKET\n");
    }
    //Otherwise, means packet is from victim.
    else{
      printf("   src_mac = %s\n", addr_ntoa(&ethhdr->eth_src));
      printf("   dst_mac = %s\n", addr_ntoa(&ethhdr->eth_dst));
      printf("   eth_type = %u\n", ntohs(ethhdr->eth_type));
      printf("   NOT REPLAYING PACKET\n");
    } 

    //Determine higher protocol
      switch(ntohs(ethhdr->eth_type)){
        case ETH_TYPE_IP:  
          read_ip(packet_buffer);
          break;
        case ETH_TYPE_ARP:
          read_arp(packet_buffer);
          break;
        default:
          printf("   OTHER\n");
          break;
      }

  }
}
void read_ip(unsigned char *packet_buffer, config_data cfg_info){
  struct ip_hdr *iphdr;
  
  iphdr = (struct ip_hdr *)(packet_buffer + ETH_HDR_LEN);
  printf("   IP\n");
  printf("      ip_len = %u\n", ntohs(iphdr->ip_len));
  
  if(addr_cmp(&iphdr->ip_src, &cfg_info.victim_ip) == 0){
    printf("      src_ip = %s\n", addr_ntoa(&iphdr->ip_src));
    printf("      dst_ip = %s\n", addr_ntoa(&cfg_info.replay_attacker_ip));
    iphdr->ip_src = cfg_info.replay_victim_ip;
    iphdr->ip_dst = cfg_info.replay_attacker_ip;
    printf("      rep_src_ip = %s\n", addr_ntoa(&iphdr->ip_src));
    printf("      rep_dst_ip = %s\n", addr_ntoa(&iphdr->ip_dst));
  }
  else{
    printf("      src_ip = %s\n", addr_ntoa(&iphdr->ip_src));
    printf("      dst_ip = %s\n", addr_ntoa(&iphdr->ip_dst));
  }
    
  unsigned int true_hdr_size = iphdr->ip_hl * 4;
  switch(iphdr->ip_p){
    case IP_PROTO_TCP:
      read_tcp(true_hdr_size, packet_buffer);
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
void read_arp(unsigned char *packet_buffer, config_data cfg_info){
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
      break;
  }
}

void read_tcp(unsigned int true_hdr_size, unsigned char *packet_buffer, config_data cfg_info){
  struct tcp_hdr *tcphdr;
  tcphdr = (struct tcp_hdr *)(packet_buffer + ETH_HDR_LEN + true_hdr_size);
  printf("      TCP\n");
  
  if((unsigned short)ntohs(tcphdr->th_sport) == (unsigned short)ntohs(cfg_info.attacker_port)){
    printf("         src_port = %u\n", (unsigned short)ntohs(tcphdr->th_sport));
    printf("         dst_port = %u\n", (unsigned short)ntohs(cfg_info.replay_attacker_port));
    tcphdr->th_sport = cfg_info.replay_victim_port;
    tcphdr->th_dport = cfg_info.replay_attacker_port;
    printf("         rep_src_port = %u\n", (unsigned short)ntohs(tcphdr->th_sport));
    printf("         rep_dst_port = %u\n", (unsigned short)ntohs(tcphdr->th_dport));
    printf("         seq = %u\n", ntohl(tcphdr->th_seq));
    printf("         ack = %u", ntohl(tcphdr->th_ack));
    send_packet();
  }
  else{
    printf("         src_port = %u\n", (unsigned short)ntohs(tcphdr->th_sport));
    printf("         dst_port = %u\n", (unsigned short)ntohs(tcphdr->th_dport));
    printf("         seq = %u\n", ntohl(tcphdr->th_seq));
    printf("         ack = %u", ntohl(tcphdr->th_ack));
  
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
config_data read_cfg(FILE *cfg_fp){
  char *line = NULL;
  size_t len = 0;
  config_data cfg_info;
  

  //Read first line (not really necessary since already have the pcap name);
  getline(&line, &len, cfg_fp);
  
  //Read victim IP
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  inet_pton(AF_INET, line, &cfg_info.victim_ip);

  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  addr_aton(line, &cfg_info.victim_mac);

  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  cfg_info.victim_port = (uint16_t)atoi(line);

  //Read attacker IP
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  inet_pton(AF_INET, line, &cfg_info.attacker_ip);
  
  //Read attacker MAC
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  addr_aton(line, &cfg_info.attacker_mac);

  //Read attacker port
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  cfg_info.attacker_port = (uint16_t)atoi(line);

  //Read replay victim IP
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  inet_pton(AF_INET, line, &cfg_info.replay_victim_ip);

  //Read replay victim MAC
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  addr_aton(line, &cfg_info.replay_victim_mac);

  //Read replay victim port
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  cfg_info.replay_victim_port = (uint16_t)atoi(line);

  //Read replay attacker IP
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  inet_pton(AF_INET, line, &cfg_info.replay_attacker_ip);
  //Read replay attacker MAC
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  addr_aton(line, &cfg_info.replay_attacker_mac);

  //Read replay attacker port
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  cfg_info.replay_attacker_port = (uint16_t)atoi(line);

  //Read interface
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  cfg_info.interface = line;

  //Read timing
  getline(&line, &len, cfg_fp);
  line[strcspn(line, "\n")] = 0;
  cfg_info.timing = line;
  free(line);
  return cfg_info;
}

void send_packet(unsigned char *packet_buffer, int len, config_data cfg_info){
  
  eth_t *eth;
  eth = eth_open(cfg_info.interface);

  
  printf("Sending packet...\n");

}
