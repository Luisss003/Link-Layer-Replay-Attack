#ifndef PKT_TRANS_H
#define PKT_TRANS_H

#include <dumbnet.h>

int init_eth(const char *interface);
void cleanup_eth();
int send_modified_packet(const unsigned char *buf, size_t len);
#endif // PKT_TRANS_H
