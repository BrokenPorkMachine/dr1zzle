#ifndef WIFI_H
#define WIFI_H

void wifi_init(void);
void wifi_scan(void);
void wifi_connect(const char *ssid, const char *pass);
void wifi_status(void);

#endif
