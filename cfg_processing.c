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


    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.victim_ip);

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &tmp_mac);
    memcpy(&cfg_info.victim_mac, &tmp_mac.addr_eth, sizeof(eth_addr_t));

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.victim_port = (uint16_t)atoi(line);

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.attacker_ip);

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &tmp_mac);
    memcpy(&cfg_info.attacker_mac, &tmp_mac.addr_eth, sizeof(eth_addr_t));

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.attacker_port = (uint16_t)atoi(line);

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.replay_victim_ip);

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &tmp_mac);
    memcpy(&cfg_info.replay_victim_mac, &tmp_mac.addr_eth, sizeof(eth_addr_t));

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.replay_victim_port = (uint16_t)atoi(line);

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    inet_pton(AF_INET, line, &cfg_info.replay_attacker_ip);

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    addr_aton(line, &tmp_mac);
    memcpy(&cfg_info.replay_attacker_mac, &tmp_mac.addr_eth, sizeof(eth_addr_t));

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.replay_attacker_port = (uint16_t)atoi(line);

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.interface = strdup(line);

    getline(&line, &len, cfg_fp);
    line[strcspn(line, "\n")] = 0;
    cfg_info.timing = strdup(line);

    free(line);
    return cfg_info;
}

void print_config(const struct config_data *cfg) {
    char ipbuf[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &cfg->victim_ip, ipbuf, sizeof(ipbuf));
    printf("victim_ip: %s\n", ipbuf);
    printf("victim_mac: %s\n", addr_ntoa((struct addr *)&cfg->victim_mac));
    printf("victim_port: %u\n", cfg->victim_port);

    inet_ntop(AF_INET, &cfg->attacker_ip, ipbuf, sizeof(ipbuf));
    printf("attacker_ip: %s\n", ipbuf);
    printf("attacker_mac: %s\n", addr_ntoa((struct addr *)&cfg->attacker_mac));
    printf("attacker_port: %u\n", cfg->attacker_port);

    inet_ntop(AF_INET, &cfg->replay_victim_ip, ipbuf, sizeof(ipbuf));
    printf("replay_victim_ip: %s\n", ipbuf);
    printf("replay_victim_mac: %s\n", addr_ntoa((struct addr *)&cfg->replay_victim_mac));
    printf("replay_victim_port: %u\n", cfg->replay_victim_port);

    inet_ntop(AF_INET, &cfg->replay_attacker_ip, ipbuf, sizeof(ipbuf));
    printf("replay_attacker_ip: %s\n", ipbuf);
    printf("replay_attacker_mac: %s\n", addr_ntoa((struct addr *)&cfg->replay_attacker_mac));
    printf("replay_attacker_port: %u\n", cfg->replay_attacker_port);

    printf("interface: %s\n", cfg->interface);
    printf("timing: %s\n", cfg->timing);
}

