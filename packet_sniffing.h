#ifndef PACKET_SNIFFING_H
#define PACKET_SNIFFING_H

#include <pcap.h>
#include "cfg_processing.h"

int init_sniffer(const char *interface);
void close_sniffer();
const u_char *receive_victim_packet(struct config_data *cfg, struct pcap_pkthdr *header);

extern uint32_t latest_victim_seq;
extern uint32_t latest_victim_ack;

#endif

