#include "maps.h"
#include "config.h"

#include <stdio.h>
#include <string.h>

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
