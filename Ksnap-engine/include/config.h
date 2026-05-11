#ifndef CONFIG_H
#define CONFIG_H

// --------------------------
// simple informing defines
#define ERROR 0
#define OK 1

#define EXIT 0
// ---------------------

typedef struct {
    char *mode;
    int pid;
    char *file_name;
    char *output_dir;
} ksnap_config_t;

#endif // !CONFIG_H
