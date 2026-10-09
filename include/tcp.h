#ifndef TCP_H
#define TCP_H

#include <stdint.h>

#define ETH_MTU 1514
#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define TCP_HDR_LEN 20

void tcp_stack_init(void);
void tcp_stack_poll(void);
void tcp_stack_process_ethernet(const uint8_t *frame, uint16_t len);

#endif
