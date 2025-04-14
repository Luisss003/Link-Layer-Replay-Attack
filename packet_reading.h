#ifndef PACKET_READING_H
#define PACKET_READING_H

#include "cfg_processing.h"

int read_cfg_file(char *);
struct config_data read_cfg(FILE *);
void read_pcap_global_header(int);
void create_att_pkt(int, FILE *);
void read_ip(unsigned char *, struct config_data *);
void read_arp(unsigned char *);
void read_tcp(unsigned int, unsigned char *, struct config_data *);
void read_udp(unsigned int, unsigned char *);
void read_icmp(unsigned int, unsigned char *);

#endif

