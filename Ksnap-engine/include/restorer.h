#ifndef _RESTORER_H
#define _RESTORER_H

#include <stdio.h>

#include "config.h"

// recreate a process from a snapshot, returns OK or ERROR
int restorer(ksnap_config_t);

#endif // !_RESTORER_H
