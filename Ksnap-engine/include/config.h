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

typedef struct {
    char *mode;
    int pid;
    char *file_name;
    char *output_dir;
} ksnap_config_t;

typedef struct vma_segment_t {
    unsigned long start_segment_address;
    unsigned long segment_size;
} vma_segment_t;

#endif // !CONFIG_H
