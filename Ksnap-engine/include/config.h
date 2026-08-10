#ifndef CONFIG_H
#define CONFIG_H

// --------------------------
// simple informing defines
#define ERROR 0
#define OK 1

#define EXIT 0

// shortest accepted path length
#define MIN_LEN_PATH 0
// ---------------------

// fixed location until -d and -n are wired up
#define KSNAP_SNAPSHOT_PATH "../save/snapshot.ksnap"

typedef struct {
    char *mode;
    int pid;
    char *file_name;
    char *output_dir;
} ksnap_config_t;

#endif // !CONFIG_H
