#ifndef MAPS_H
#define MAPS_H

#include <linux/limits.h>
#include <stdbool.h>
#include <sys/types.h>

// a path can be as long as PATH_MAX so a whole line must fit in one piece
#define MAPS_LINE_MAX (PATH_MAX + 128)

// one parsed line of /proc/pid/maps
typedef struct {
    unsigned long start;
    unsigned long end;
    unsigned long file_offset;
    char privileges[5];
    char path[PATH_MAX];
} maps_line_t;

bool parse_maps_line(const char *maps_line, maps_line_t *parsed);

// kernel owned mapping that has to keep its address across a restore
bool is_kernel_map(const char *maps_path);

// find a named mapping in a live process - returns OK or ERROR
int find_named_map(pid_t pid, const char *name, unsigned long *start,
                   unsigned long *size);

#endif // MAPS_H
