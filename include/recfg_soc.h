#ifndef RECFG_SOC_H
#define RECFG_SOC_H

#include "recfg.h"

void recfg_soc_setup(void);
void recfg_soc_sync(void);
void recfg_soc_lock(void);
void recfg_cmd(const char *cmd, char *args);

#endif /* RECFG_SOC_H */