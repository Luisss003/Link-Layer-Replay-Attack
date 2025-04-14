#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "packet_reading.h"

int main(int argc, char *argv[]) {
    int send_packets = 0;
    char *cfg_file;

    // Check arguments: allow optional -s
    if (argc == 3 && strcmp(argv[1], "-s") == 0) {
        send_packets = 1;
        cfg_file = argv[2];
    } else if (argc == 2) {
        cfg_file = argv[1];
    } else {
        fprintf(stderr, "Usage: %s [-s] <config_file>\n", argv[0]);
        return 1;
    }

    parse_pcap(cfg_file, send_packets);
    printf("\n");

    return 0;
}
