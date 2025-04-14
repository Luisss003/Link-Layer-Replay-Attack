#ifndef CFG_PROCESSING_H
#define CFG_PROCESSING_H

#include <stdio.h>
#include <stdint.h>
#include <dumbnet.h> 

struct config_data read_cfg(FILE *);

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
};

#endif
