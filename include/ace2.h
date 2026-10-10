#ifndef ACE2_H
#define ACE2_H

#define ACE2_MAX_PORTS 8

void ace2_init(void);
void ace2_dump(void);
void ace2_port_reset(int port);
void ace2_port_enable(int port);
void ace2_dump_port_status(int port);

#endif
