#include "maps.h"
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h> // for PROT_* and MAP_*

#define MAPS_PATH_WIDTH "4095"
_Static_assert(PATH_MAX == 4096, "MAPS_PATH_WIDTH must be PATH_MAX - 1");

bool parse_maps_line(const char *maps_line, maps_line_t *parsed) {
    parsed->privileges[0] = '\0';
    parsed->path[0] = '\0';
    parsed->file_offset = 0;

    //
    // format is like this to parse
    // 08048000-08049000 r-xp 00000000 03:00 8312       /opt/test
    // 08050000-08051000 rw-p 00000000 00:00 0
    // the last field is optional - anonymous mappings carry no path
    //
    // device and inode are skipped as plain tokens
    // suppressed conversions do not count so sscanf returns 5 at most
    int parsed_fields =
        sscanf(maps_line, "%lx-%lx %4s %lx %*s %*s %" MAPS_PATH_WIDTH "s",
               &parsed->start, &parsed->end, parsed->privileges,
               &parsed->file_offset, parsed->path);

    // only the path is optional
    if (parsed_fields < 4)
        return false;

    if (strlen(parsed->privileges) != 4)
        return false;

    if (parsed->end <= parsed->start)
        return false;

    return true;
}

bool is_kernel_map(const char *maps_path) {
    // [vsyscall] is left out on purpose - it never changes address
    return strcmp(maps_path, "[vdso]") == 0 ||
           strncmp(maps_path, "[vvar", 5) == 0;
}

// a bracketed name is a kernel owned pseudo mapping, and only the heap and the
// stack of those carry process state worth copying
static bool is_dumpable_path(const char *maps_path) {
    if (maps_path[0] != '[')
        return true; // anonymous mapping or a regular file

    return strcmp(maps_path, "[heap]") == 0 ||
           strcmp(maps_path, "[stack]") == 0;
}

vma_class_t classify_maps_line(const maps_line_t *parsed) {
    // the content is useless to copy but the address has to come back
    if (is_kernel_map(parsed->path))
        return VMA_KERNEL;

    if (parsed->privileges[0] != 'r')
        return VMA_SKIP_UNREADABLE;

    // a shared mapping belongs to more than one process, so writing it back
    // into a fresh process would be wrong and restoring it is out of scope
    if (parsed->privileges[3] != 'p')
        return VMA_SKIP_SHARED;

    if (!is_dumpable_path(parsed->path))
        return VMA_SKIP_PSEUDO;

    return VMA_DUMP;
}

uint32_t perms_to_prot(const char privileges[5]) {
    uint32_t prot = PROT_NONE;

    if (privileges[0] == 'r')
        prot |= PROT_READ;
    if (privileges[1] == 'w')
        prot |= PROT_WRITE;
    if (privileges[2] == 'x')
        prot |= PROT_EXEC;

    return prot;
}

uint32_t perms_to_map_flags(const char privileges[5]) {
    return privileges[3] == 'p' ? MAP_PRIVATE : MAP_SHARED;
}

int find_named_map(pid_t pid, const char *name, unsigned long *start,
                   unsigned long *size) {
    char process_path[64];
    snprintf(process_path, sizeof(process_path), "/proc/%d/maps", pid);

    FILE *maps_file_handle = fopen(process_path, "r");
    if (maps_file_handle == NULL) {
        perror("Error during opening the virtual file (proc/pid/maps)");
        return ERROR;
    }

    char maps_line[MAPS_LINE_MAX];
    maps_line_t parsed;
    int result = ERROR;

    while (fgets(maps_line, sizeof(maps_line), maps_file_handle) != NULL) {
        if (!parse_maps_line(maps_line, &parsed))
            continue;

        if (strcmp(parsed.path, name) == 0) {
            *start = parsed.start;
            *size = parsed.end - parsed.start;
            result = OK;
            break;
        }
    }

    fclose(maps_file_handle);
    return result;
}
