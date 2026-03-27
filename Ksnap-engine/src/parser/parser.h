#ifndef PARSER_H
#define PARSER_H

#include <unistd.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DUMPER_LEN (sizeof("DUMP") - 1)
#define RESTORER_LEN (sizeof("RESTORE") - 1)

#define LIST_OF_MODES                                                          \
    X(DUMP)                                                                    \
    X(RESTORE)                                                                 \
    X(ERROR)

#define X(name) name,
typedef enum modes_t { LIST_OF_MODES } modes_t;
#undef X

static inline char *mode_to_string(modes_t mode) {
    switch (mode) {
#define X(name)                                                                \
    case name:                                                                 \
        return #name;
        LIST_OF_MODES
#undef X
    }
}

typedef struct {
    char *mode;
    int pid;
    char *file_name;
    char *output_dir;
} ksync_config_t;

static inline modes_t validate_mode(char *arg);
static inline void set_config_mode(ksync_config_t *config, modes_t mode);

static inline bool validate_pid(char *arg);
static inline void set_config_pid(ksync_config_t *config, int pid);

static inline ksync_config_t parse_arg(int argc, char **argv) {

    int opt;
    int pid;
    modes_t mode;

    ksync_config_t config = {0};

    while ((opt = getopt(argc, argv, "m:p:hn")) != -1) {
        switch (opt) {
        case 'm':
            mode = validate_mode(optarg);
            set_config_mode(&config, mode);
            break;

        case 'p':
            if (validate_pid(optarg)) {
                pid = atoi(optarg);
                set_config_pid(&config, pid);
            }
            break;

        case 'h':
            printf("h flag added\n");
            break;

        case 'n':
            printf("n flag added\n");
            break;
        }
    }

    return config;
}

static inline modes_t validate_mode(char *arg) {
    if (!strncmp(arg, "Dump", DUMPER_LEN)) {
        return DUMP;
    } else if (!strncmp(arg, "Restore", RESTORER_LEN)) {
        return RESTORE;
    }
    // handle unregonized mode
    return ERROR;
}
static inline void set_config_mode(ksync_config_t *config, modes_t mode) {
    config->mode = mode_to_string(mode);
}

static inline bool validate_pid(char *arg) {
    int size = strlen(arg);
    if (size > 7) {
        return false;
    }

    for (int i = 0; i < size; i++) {
        if (!isdigit(arg[i]))
            return false;
    }
    return true;
}
static inline void set_config_pid(ksync_config_t *config, int pid) {
    config->pid = pid;
}

#endif // !PARSER_H
