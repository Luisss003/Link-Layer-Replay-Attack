#ifndef PKT_TRANS_H
#define PKT_TRANS_H

#include <dumbnet.h>
#include "cfg_processing.h"
int init_eth(const char *interface);
void cleanup_eth();
int send_modified_packet(const unsigned char *buf, int len, struct config_data *);

#endif 
