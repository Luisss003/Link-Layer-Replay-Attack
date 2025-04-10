#ifndef FILE_INFO_H
#define FILE_INFO_H

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC 0xd4c3b2a1
#define PCAP_MODIFIED_MAGIC 0xa1b2cd34
#define PCAP_SWAPPED_MODIFIED_MAGIC 0x34cdb2a1

struct timev {
  unsigned int tv_sec;
  unsigned int tv_usec;
};

struct my_pkthdr {
  struct timev ts;
  int caplen;
  int len;
};

struct config_data {
  ip_addr_t victim_ip;
  eth_addr_t victim_mac;
  uint16_t victim_port;
  ip_addr_t attacker_ip;
  eth_addr_t attacker_mac;
  uint16_t attacker_port;
  ip_addr_t replay_victim_ip;
  eth_addr_t replay_victim_mac;
  uint16_t replay_victim_port;
  ip_addr_t replay_attacker_ip;
  eth_addr_t replay_attacker_mac;
  uint16_t replay_attacker_port;
  char *interface;
  char *timing;
}
#endif
