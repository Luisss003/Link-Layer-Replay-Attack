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

#endif
