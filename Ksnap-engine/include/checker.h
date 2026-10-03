#ifndef CHECKER_H
#define CHECKER_H

#include "config.h"

// Check mode answers, before anything is written, whether this engine can dump
// and restore a process. It is the authority on that question: the web panel
// used to reimplement the rules of the dumper in Python, which meant two copies
// of one truth. See docs/markdown/check_mode.md for the output contract.
//
// With -p one report is printed, without -p every process in /proc gets one.
// Output is one JSON object per line.

// exit codes, so a shell can branch without parsing the output
#define KSNAP_CHECK_EXIT_DUMPABLE 0
#define KSNAP_CHECK_EXIT_ERROR 1
#define KSNAP_CHECK_EXIT_BLOCKED 11

int check(ksnap_config_t config);

#endif // CHECKER_H
