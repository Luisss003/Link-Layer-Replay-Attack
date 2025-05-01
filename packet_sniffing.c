#include "packet_sniffing.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static pcap_t *pcap_handle = NULL;
uint32_t latest_victim_seq = 0;
uint32_t latest_victim_ack = 0;

int init_sniffer(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Create handle in non-blocking mode
    pcap_handle = pcap_create(interface, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "pcap_create: %s\n", errbuf);
        return -1;
    }

    // Enable non-blocking mode
    if (pcap_setnonblock(pcap_handle, 1, errbuf) != 0) {
        fprintf(stderr, "pcap_setnonblock: %s\n", pcap_geterr(pcap_handle));
        return -1;
    }

    // (These don't have effect but included per prof)
    pcap_set_timeout(pcap_handle, 80);
    pcap_set_immediate_mode(pcap_handle, 1);

    if (pcap_activate(pcap_handle) != 0) {
        fprintf(stderr, "pcap_activate: %s\n", pcap_geterr(pcap_handle));
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

    for (int attempts = 0; attempts < 1000; attempts++) {
        packet = pcap_next(pcap_handle, header);
        if (packet == NULL) {
            usleep(500);  // small delay to avoid CPU spin
            continue;
        }

        struct eth_hdr *ethhdr = (struct eth_hdr *)packet;
        if (ntohs(ethhdr->eth_type) != ETH_TYPE_IP)
            continue;

        struct ip_hdr *iphdr = (struct ip_hdr *)(packet + ETH_HDR_LEN);
        if (iphdr->ip_p != IP_PROTO_TCP)
            continue;

        // Check if this is a packet from the victim
        if (memcmp(&iphdr->ip_src, &cfg->replay_victim_ip, sizeof(ip_addr_t)) == 0) {
            struct tcp_hdr *tcphdr = (struct tcp_hdr *)((u_char *)iphdr + (iphdr->ip_hl * 4));

            uint16_t ip_len = ntohs(iphdr->ip_len);
            uint16_t ip_hdr_len = iphdr->ip_hl * 4;
            uint16_t tcp_hdr_len = tcphdr->th_off * 4;

            uint16_t payload_len = 0;
            if (ip_len >= ip_hdr_len + tcp_hdr_len)
                payload_len = ip_len - ip_hdr_len - tcp_hdr_len;

            uint32_t inc = payload_len;
			if(tcphdr->th_flags & (TH_SYN | TH_FIN)){
				inc += 1;
			}
			latest_victim_seq = ntohl(tcphdr->th_seq) + inc;
			latest_victim_ack = ntohl(tcphdr->th_ack);

            printf("Sniffed victim packet: seq = %u, ack = %u, payload_len = %u\n",
                   ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack), payload_len);

            return packet;
        }
    }

    printf("Timed out waiting for victim packet\n");
    return NULL;

}
