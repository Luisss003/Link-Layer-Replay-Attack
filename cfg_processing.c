#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <dumbnet.h>
#include "cfg_processing.h"

struct config_data read_cfg(FILE *cfg_fp) {
    char *line = NULL;
    size_t len = 0;
    struct config_data cfg_info;
    struct addr tmp_mac;

    // Skip pcap filename

    // Victim IP
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.victim_ip);

    // Victim MAC
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &tmp_mac);
    memcpy(&cfg_info.victim_mac, &tmp_mac.addr_eth, sizeof(eth_addr_t));

    // Victim port
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.victim_port = (uint16_t)atoi(line);

    // Attacker IP
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.attacker_ip);

    // Attacker MAC
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &tmp_mac);
    memcpy(&cfg_info.attacker_mac, &tmp_mac.addr_eth, sizeof(eth_addr_t));

    // Attacker port
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.attacker_port = (uint16_t)atoi(line);

    // Replay victim IP
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.replay_victim_ip);

    // Replay victim MAC
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &tmp_mac);
    memcpy(&cfg_info.replay_victim_mac, &tmp_mac.addr_eth, sizeof(eth_addr_t));

    // Replay victim port
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.replay_victim_port = (uint16_t)atoi(line);

    // Replay attacker IP
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.replay_attacker_ip);

    // Replay attacker MAC
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &tmp_mac);
    memcpy(&cfg_info.replay_attacker_mac, &tmp_mac.addr_eth, sizeof(eth_addr_t));

    // Replay attacker port
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.replay_attacker_port = (uint16_t)atoi(line);

    // Interface
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.interface = strdup(line);

    // Timing
    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.timing = strdup(line);

    free(line);
    return cfg_info;
}
