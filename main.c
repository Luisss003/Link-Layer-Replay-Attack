#include <pcap.h>
#include "pkt_trans.h"
#include "packet_reading.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s [-s] <config file>\n", argv[0]);
        return 1;
    }

    read_cfg_file(argv[1]);
    cleanup_eth();
    printf("\n");
    return 0;
}

