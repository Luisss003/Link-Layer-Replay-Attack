#ifndef PACKET_READING_H
#define PACKET_READING_H

int parse_pcap(char *, int);
void read_pcap_global_header(int);
void create_attack_packets(int, FILE *);
void read_ip(unsigned char *, config_data);
void read_arp(unsigned char *, config_data);
void read_tcp(unsigned int, unsigned char *, config_data);
void read_udp(unsigned int, unsigned char *, config_data);
void read_icmp(unsigned int, unsigned char *, config_data);
config_data read_cfg(FILE *);
void send_packet(unsigend char *, int, config_data);

#endif
