#ifndef MAPS_H
#define MAPS_H

#include <linux/limits.h>
#include <stdbool.h>
#include <stdint.h>
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

// what the engine does with one mapping. Dump and Check both decide through
// classify_maps_line, so there is a single answer per mapping instead of one
// rule inside the dumper and another one somewhere else.
typedef enum {
    VMA_DUMP,            // copied into the snapshot, content included
    VMA_KERNEL,          // only address and name are kept, content skipped
    VMA_SKIP_UNREADABLE, // no read bit, nothing to copy
    VMA_SKIP_SHARED,     // MAP_SHARED, the engine cannot carry it over
    VMA_SKIP_PSEUDO      // [vsyscall] and other kernel owned pseudo mappings
} vma_class_t;

vma_class_t classify_maps_line(const maps_line_t *parsed);

// PROT_* and MAP_* of one mapping, derived from its privileges field
uint32_t perms_to_prot(const char privileges[5]);
uint32_t perms_to_map_flags(const char privileges[5]);

// find a named mapping in a live process - returns OK or ERROR
int find_named_map(pid_t pid, const char *name, unsigned long *start,
                   unsigned long *size);

#endif // MAPS_H
