#ifndef PARSER_H
#define PARSER_H

#include <unistd.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// relative path right now but in future need to change in makefile
#include "../config.h"
//

#define DUMP_LEN (sizeof("DUMP") - 1)
#define RESTORE_LEN (sizeof("RESTORE") - 1)

typedef enum ksnap_status_t {
    KSNAP_OK = 0,
    KSNAP_ERR_INVALID_PID = -1,
    KSNAP_ERR_INVALID_MODE = -2,
    KSNAP_ERR_NO_MODE_SPECIFIED = -3,
    KSNAP_ERR_NO_PID_SPECIFIED = -4,
    KSNAP_ERR_INVALID_NAME = -5,
    KSNAP_ERR_MISSING_ARGS = -6,
    KSNAP_ERR_TOO_MUCH_ARGS = -7,
    KSNAP_ERR_INVALID_ARGS = -8
} ksnap_status_t;

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

static inline ksnap_status_t validate_mode(char *arg, modes_t *mode);
static inline void set_config_mode(ksnap_config_t *config, modes_t mode);

static inline ksnap_status_t validate_pid(char *arg);
static inline void set_config_pid(ksnap_config_t *config, int pid);

static inline ksnap_status_t validate_mandatory_args(ksnap_config_t *config);

static inline bool check_status(ksnap_status_t *status);

static inline ksnap_status_t parse_arg(int argc, char **argv,
                                       ksnap_config_t *config) {
    // initializate config struct to default values
    config->mode = NULL;
    config->pid = -1;
    config->file_name = NULL;
    config->output_dir = NULL;

    int opt;
    int pid;
    modes_t mode;
    ksnap_status_t status = KSNAP_ERR_MISSING_ARGS;

    while ((opt = getopt(argc, argv, "m:p:hn")) != -1) {
        switch (opt) {
        case 'm':
            status = validate_mode(optarg, &mode);

            if (status != KSNAP_OK)
                return status;

            set_config_mode(config, mode);

            break;

        case 'p':
            status = validate_pid(optarg);

            if (status != KSNAP_OK)
                return status;

            pid = atoi(optarg);
            set_config_pid(config, pid);

            break;

        case 'h':
            printf("Usage: Ksnap -m <mode> -p <pid> [OPTIONS]\n\n");
            printf("A checkpoint/restore engine for Linux.\n\n");
            printf("Options:\n");
            printf("  -m <mode>    Operation mode: 'Dump' or 'Restore' "
                   "(Required)\n");
            printf("  -p <pid>     Target process ID (Required)\n");
            printf("  -n <name>    Target file name for saving/restoring "
                   "memory\n");
            printf("  -d <path>    Directory path for output/input files\n");
            printf("  -h           Show this help message and exit\n\n");
            printf("Example:\n");
            printf("  sudo ./Ksnap -m Dump -p 1234 -n memory_dump -d "
                   "/tmp/ksnap\n");
            break;

        case 'n':
            printf("n flag added\n");
            break;
        }
    }

    status = validate_mandatory_args(config);
    return status;
}

static inline ksnap_status_t validate_mode(char *arg, modes_t *mode) {

    // bug here (only work for DUMP)
    // Dump 4 letters
    // Restore 7 letters

    if (!strncmp(arg, "Dump", DUMP_LEN) && strlen(arg) == DUMP_LEN) {
        *mode = DUMP;
        return KSNAP_OK;
    } else if (!strncmp(arg, "Restore", RESTORE_LEN) &&
               strlen(arg) == RESTORE_LEN) {
        *mode = RESTORE;
        return KSNAP_OK;
    }
    return KSNAP_ERR_INVALID_MODE;
}

static inline void set_config_mode(ksnap_config_t *config, modes_t mode) {
    config->mode = mode_to_string(mode);
}

static inline ksnap_status_t validate_pid(char *arg) {
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
static inline void set_config_pid(ksnap_config_t *config, int pid) {
    config->pid = pid;
}

static inline ksnap_status_t validate_mandatory_args(ksnap_config_t *config) {
    ksnap_status_t status;

    // -m for mode is required
    if (config->mode == NULL) {
        status = KSNAP_ERR_NO_MODE_SPECIFIED;
        return status;
    }

    // you cannot run Dump mode without pid specified
    if (!strncmp(config->mode, "DUMP", DUMP_LEN) && config->pid == -1) {
        status = KSNAP_ERR_NO_PID_SPECIFIED;
        return status;
    }

    return KSNAP_OK;
}

static inline bool check_status(ksnap_status_t *status) {
    switch (*status) {
    case KSNAP_OK:
        return OK;
    case KSNAP_ERR_INVALID_PID:
        fprintf(stderr, "Pid is incorrect\n");
        break;
    case KSNAP_ERR_INVALID_MODE:
        fprintf(stderr, "Mode not recognized\n");
        break;
    case KSNAP_ERR_NO_MODE_SPECIFIED:
        fprintf(stderr, "Mode not specified\n");
        break;
    case KSNAP_ERR_NO_PID_SPECIFIED:
        fprintf(stderr, "Pid no specified\n");
        break;
    case KSNAP_ERR_INVALID_NAME:
        fprintf(stderr, "File name is incorrect\n");
        break;
    case KSNAP_ERR_MISSING_ARGS:
        fprintf(stderr, "Missing args see -h for more details\n");
        break;
    case KSNAP_ERR_TOO_MUCH_ARGS:
        fprintf(stderr, "To much args see -h for more details\n");
        break;
    case KSNAP_ERR_INVALID_ARGS:
        fprintf(stderr, "Invalid args \n");
        break;
    }
    return ERROR;
}

#endif // !PARSER_H
