#ifndef DUMPER_H
#define DUMPER_H

#include <stdio.h>

#include "config.h"

// create snapshot of process, returns OK or ERROR
int dump(ksnap_config_t);

#endif // DUMPER_H
