#include <stdio.h>
#include <stdlib.h>
#include <dumbnet.h>
#include "pkt_trans.h"

static eth_t *eth_handle = NULL;

int init_eth(const char *interface) {
    eth_handle = eth_open(interface);
    if (!eth_handle) {
        perror("eth_open");
        return -1;
    }
    return 0;
}

void cleanup_eth() {
    if (eth_handle) {
        eth_close(eth_handle);
        eth_handle = NULL;
    }
}

int send_modified_packet(const unsigned char *buf, size_t len) {
    if (!eth_handle) {
        fprintf(stderr, "Error: eth_handle is NULL. Did you call init_eth()?\n");
        return -1;
    }

    int sent = eth_send(eth_handle, buf, len);
    if (sent < 0) {
        perror("eth_send");
        return -1;
    } else if ((size_t)sent != len) {
        fprintf(stderr, "Partial packet transmission: %d/%zu bytes\n", sent, len);
        return -1;
    }

    return 0;
}
