#ifndef CONFIG_H
#define CONFIG_H

#include <linux/limits.h>
#include <stdio.h>

// --------------------------
// simple informing defines
#define ERROR 0
#define OK 1

#define EXIT 0

// shortest accepted path length
#define MIN_LEN_PATH 0
// ---------------------

// used when -d or -n are not given, keeps the historical snapshot location
#define KSNAP_DEFAULT_SNAPSHOT_DIR "../save"
#define KSNAP_DEFAULT_SNAPSHOT_NAME "snapshot.ksnap"

typedef struct {
    char *mode;
    int pid;
    char *file_name;
    char *output_dir;
} ksnap_config_t;

// join the directory and the file name of the snapshot into one path
static inline int build_snapshot_path(const ksnap_config_t *config,
                                      char out[PATH_MAX]) {
    const char *dir = (config->output_dir != NULL) ? config->output_dir
                                                   : KSNAP_DEFAULT_SNAPSHOT_DIR;
    const char *name = (config->file_name != NULL)
                           ? config->file_name
                           : KSNAP_DEFAULT_SNAPSHOT_NAME;

    int written = snprintf(out, PATH_MAX, "%s/%s", dir, name);

    if (written < 0 || written >= PATH_MAX) {
        fprintf(stderr, "Error: snapshot path is too long\n");
        return ERROR;
    }

    return OK;
}

#endif // !CONFIG_H
