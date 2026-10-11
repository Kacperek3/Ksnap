#ifndef PARSER_H
#define PARSER_H

#include <unistd.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// relative path right now but in future need to change in makefile
#include "config.h"
//

#define DUMP_LEN (sizeof("DUMP") - 1)
#define RESTORE_LEN (sizeof("RESTORE") - 1)
#define CHECK_LEN (sizeof("CHECK") - 1)

typedef enum ksnap_status_t {
    KSNAP_OK = 0,
    KSNAP_ERR_INVALID_PID = -1,
    KSNAP_ERR_INVALID_MODE = -2,
    KSNAP_ERR_NO_MODE_SPECIFIED = -3,
    KSNAP_ERR_NO_PID_SPECIFIED = -4,
    KSNAP_ERR_INVALID_NAME = -5,
    KSNAP_ERR_MISSING_ARGS = -6,
    KSNAP_ERR_TOO_MUCH_ARGS = -7,
    KSNAP_ERR_INVALID_ARGS = -8,
    KSNAP_ERR_KILL_WITHOUT_DUMP = -9
} ksnap_status_t;

#define LIST_OF_MODES                                                          \
    X(DUMP)                                                                    \
    X(RESTORE)                                                                 \
    X(CHECK)

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
    return NULL;
}

static inline ksnap_status_t validate_mode(char *arg, modes_t *mode);
static inline void set_config_mode(ksnap_config_t *config, modes_t mode);

static inline ksnap_status_t validate_pid(char *arg);
static inline void set_config_pid(ksnap_config_t *config, int pid);

static inline ksnap_status_t validate_name(char *arg);
static inline void set_config_file_name(ksnap_config_t *config, char *name);

static inline ksnap_status_t validate_dir(char *arg);
static inline void set_config_output_dir(ksnap_config_t *config, char *dir);

static inline ksnap_status_t validate_mandatory_args(ksnap_config_t *config);

static inline bool check_status(ksnap_status_t *status);

static inline ksnap_status_t parse_arg(int argc, char **argv,
                                       ksnap_config_t *config) {
    // initializate config struct to default values
    config->mode = NULL;
    config->pid = -1;
    config->file_name = NULL;
    config->output_dir = NULL;
    config->kill_after_dump = false;

    int opt;
    int pid;
    modes_t mode;
    ksnap_status_t status = KSNAP_ERR_MISSING_ARGS;

    while ((opt = getopt(argc, argv, "m:p:n:d:kh")) != -1) {
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
            printf("  -m <mode>    Operation mode: 'Dump', 'Restore' or "
                   "'Check' (Required)\n");
            printf("  -p <pid>     Target process ID (Required for Dump, "
                   "optional for Check)\n");
            printf("  -n <name>    Target file name for saving/restoring "
                   "memory\n");
            printf("  -d <path>    Directory path for output/input files\n");
            printf("  -k           Dump only: terminate the process once the "
                   "snapshot\n");
            printf("               is written, it never runs past the "
                   "snapshot\n");
            printf("  -h           Show this help message and exit\n\n");
            printf("Check mode reports, as one JSON object per line, "
                   "whether a process\n");
            printf("can be dumped and restored. Without -p it reports on "
                   "every process.\n");
            printf("Exit codes: 0 dumpable, 11 not dumpable, 1 error.\n\n");
            printf("Examples:\n");
            printf("  sudo ./Ksnap -m Dump -p 1234 -n memory_dump -d "
                   "/tmp/ksnap\n");
            printf("  sudo ./Ksnap -m Dump -p 1234 -k\n");
            printf("  sudo ./Ksnap -m Check -p 1234\n");
            printf("  sudo ./Ksnap -m Check\n");
            // nothing else makes sense after the usage was asked for
            exit(EXIT_SUCCESS);

        case 'n':
            status = validate_name(optarg);

            if (status != KSNAP_OK)
                return status;

            set_config_file_name(config, optarg);

            break;

        case 'k':
            config->kill_after_dump = true;
            break;

        case 'd':
            status = validate_dir(optarg);

            if (status != KSNAP_OK)
                return status;

            set_config_output_dir(config, optarg);

            break;

        default:
            return KSNAP_ERR_INVALID_ARGS;
        }
    }

    status = validate_mandatory_args(config);
    return status;
}

static inline ksnap_status_t validate_mode(char *arg, modes_t *mode) {
    // the length is compared as well, so "Dumpster" is not taken for "Dump"
    if (!strncmp(arg, "Dump", DUMP_LEN) && strlen(arg) == DUMP_LEN) {
        *mode = DUMP;
        return KSNAP_OK;
    } else if (!strncmp(arg, "Restore", RESTORE_LEN) &&
               strlen(arg) == RESTORE_LEN) {
        *mode = RESTORE;
        return KSNAP_OK;
    } else if (!strncmp(arg, "Check", CHECK_LEN) && strlen(arg) == CHECK_LEN) {
        *mode = CHECK;
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

// the name has to stay a single file inside the given directory, a path
// separator here would silently write the snapshot somewhere else
static inline ksnap_status_t validate_name(char *arg) {
    size_t size = strlen(arg);

    if (size == 0 || size > NAME_MAX)
        return KSNAP_ERR_INVALID_NAME;

    if (strchr(arg, '/') != NULL)
        return KSNAP_ERR_INVALID_NAME;

    if (!strcmp(arg, ".") || !strcmp(arg, ".."))
        return KSNAP_ERR_INVALID_NAME;

    return KSNAP_OK;
}

static inline void set_config_file_name(ksnap_config_t *config, char *name) {
    // argv lives as long as the program so the pointer can be kept as is
    config->file_name = name;
}

// room is left for a separator and the shortest possible file name
static inline ksnap_status_t validate_dir(char *arg) {
    size_t size = strlen(arg);

    if (size <= MIN_LEN_PATH || size > PATH_MAX - NAME_MAX - 2)
        return KSNAP_ERR_INVALID_ARGS;

    return KSNAP_OK;
}

static inline void set_config_output_dir(ksnap_config_t *config, char *dir) {
    config->output_dir = dir;
}

static inline ksnap_status_t validate_mandatory_args(ksnap_config_t *config) {
    ksnap_status_t status;

    // -m for mode is required
    if (config->mode == NULL) {
        status = KSNAP_ERR_NO_MODE_SPECIFIED;
        return status;
    }

    // you cannot run Dump mode without pid specified
    //
    // Check takes it as optional on purpose: without a pid it reports on every
    // process in /proc, which is how the panel fills its process list
    if (!strncmp(config->mode, "DUMP", DUMP_LEN) && config->pid == -1) {
        status = KSNAP_ERR_NO_PID_SPECIFIED;
        return status;
    }

    // ending a process is only ever the second half of a dump, a Restore or a
    // Check with -k would end nothing, and silently ignoring it would hide a
    // mistake in the caller
    if (config->kill_after_dump &&
        strncmp(config->mode, "DUMP", DUMP_LEN) != 0) {
        status = KSNAP_ERR_KILL_WITHOUT_DUMP;
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
    case KSNAP_ERR_KILL_WITHOUT_DUMP:
        fprintf(stderr, "-k can only be used with Dump\n");
        break;
    }
    return ERROR;
}

#endif // !PARSER_H
