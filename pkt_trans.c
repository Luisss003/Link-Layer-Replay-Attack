#include <stdio.h>
#include <stdlib.h>
#include <dumbnet.h>
#include "pkt_trans.h"
#include <time.h>
#include <string.h>
#include <unistd.h>
static eth_t *eth_handle = NULL;

int init_eth(const char *interface) {
    eth_handle = eth_open(interface);
    if (eth_handle == NULL) {
        printf("ERROR: Error opening the interface :^(\n");
        return -1;
    }
    return 0;
}

void cleanup_eth() {
    if (eth_handle != NULL) {
        eth_close(eth_handle);
        eth_handle = NULL;
    }
}

int send_modified_packet(const unsigned char *buf, int len, struct config_data *cfg) {

    if (eth_handle == NULL) {
        printf("ERROR: Couldn't open ethernet handle");
		return -1;
    }

	int sent;
	if(strcmp(cfg->timing, "delay") == 0){
    	usleep(500);
		sent = eth_send(eth_handle, buf, len);
	}
	else{
		sent = eth_send(eth_handle, buf, len);
	}
	if (sent < 0) {
        printf("eth_send");
        return -1;
    } 
	else if (sent != len) {
        printf("ERROR: sent wrong amount of bytes");
		return -1;
    }

    return 0;
}
