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

typedef enum ksync_status_t {
    KSNAP_OK = 0,
    KSNAP_ERR_MISSING_ARGS = -1,
    KSNAP_ERR_INVALID_PID = -2,
    KSNAP_ERR_INVALID_MODE = -3,
    KSANP_ERR_INVALID_NAME = -4,
    KSNAP_ERR_TOO_MUCH_ARGS = -5
} ksync_status_t;

#define LIST_OF_MODES                                                          \
    X(DUMP)                                                                    \
    X(RESTORE)

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

static inline ksync_status_t validate_mode(char *arg, modes_t *mode);
static inline void set_config_mode(ksync_config_t *config, modes_t mode);

static inline ksync_status_t validate_pid(char *arg);
static inline void set_config_pid(ksync_config_t *config, int pid);

static inline ksync_status_t parse_arg(int argc, char **argv,
                                       ksync_config_t *config) {
    int opt;
    int pid;
    modes_t mode;
    ksync_status_t status;

    while ((opt = getopt(argc, argv, "m:p:hn")) != -1) {
        switch (opt) {
        case 'm':
            status = validate_mode(optarg, &mode);
            set_config_mode(config, mode);
            if (status < 0)
                return status;

            break;

        case 'p':
            if (validate_pid(optarg)) {
                pid = atoi(optarg);
                set_config_pid(config, pid);
            }
            if (status < 0)
                return status;
            break;

        case 'h':
            printf("h flag added\n");
            break;

        case 'n':
            printf("n flag added\n");
            break;
        }
    }

    return status;
}

static inline ksync_status_t validate_mode(char *arg, modes_t *mode) {
    if (!strncmp(arg, "Dump", DUMPER_LEN)) {
        *mode = DUMP;
        return KSNAP_OK;
    } else if (!strncmp(arg, "Restore", RESTORER_LEN)) {
        *mode = RESTORE;
        return KSNAP_OK;
    }
    return KSNAP_ERR_INVALID_MODE;
}
static inline void set_config_mode(ksync_config_t *config, modes_t mode) {
    config->mode = mode_to_string(mode);
}

static inline ksync_status_t validate_pid(char *arg) {
    int size = strlen(arg);
    if (size > 7) {
        return KSNAP_ERR_INVALID_PID;
    }

    for (int i = 0; i < size; i++) {
        if (!isdigit(arg[i]))
            return KSNAP_ERR_INVALID_PID;
    }
    return KSNAP_OK;
}
static inline void set_config_pid(ksync_config_t *config, int pid) {
    config->pid = pid;
}

#endif // !PARSER_H
