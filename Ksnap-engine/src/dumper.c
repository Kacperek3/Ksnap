#include <stddef.h>
#include <stdio.h>
#include <sys/ptrace.h> // for ptrace
#include <sys/user.h>   // for user_regs_struct

#include <sys/types.h>
#include <sys/wait.h> // for waitpid

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h> // for PROT_* and MAP_*
#include <unistd.h>

#include "config.h"
#include "dump_format.h"
#include "dumper.h"
#include "maps.h"
#include <fcntl.h>

#define VMA_TABLE_INITIAL_CAPACITY 64
#define PATH_POOL_INITIAL_CAPACITY 4096

// private main functions
static int read_regs(pid_t pid, struct user_regs_struct *regs);
static int read_exe_path(pid_t pid, char exe_path[PATH_MAX],
                         uint32_t *exe_path_len);
static int collect_vmas(pid_t pid, vma_descriptor_t **out_vmas,
                        uint32_t *out_count, char **out_pool,
                        uint64_t *out_pool_size, kernel_map_t *kernel_maps,
                        uint32_t *out_kernel_map_count);
static int write_snapshot(pid_t pid, const struct user_regs_struct *regs,
                          const char *exe_path, uint32_t exe_path_len,
                          vma_descriptor_t *vmas, uint32_t vma_count,
                          const char *pool, uint64_t pool_size,
                          const kernel_map_t *kernel_maps,
                          uint32_t kernel_map_count);
//
static int write_vma_payload(FILE *snapshot_handle, int mem_vma_handle,
                             const vma_descriptor_t *vma, char buff[]);
static bool is_dumpable_path(const char *maps_path);
static uint32_t perms_to_prot(const char privileges[5]);
static uint32_t perms_to_map_flags(const char privileges[5]);

int dump(ksnap_config_t config) {
    int status;
    int result = ERROR;

    struct user_regs_struct regs;
    char exe_path[PATH_MAX];
    uint32_t exe_path_len = 0;
    vma_descriptor_t *vmas = NULL;
    uint32_t vma_count = 0;
    char *path_pool = NULL;
    uint64_t path_pool_size = 0;
    kernel_map_t kernel_maps[KSNAP_MAX_KERNEL_MAPS];
    uint32_t kernel_map_count = 0;

    // attach process to our program
    if (ptrace(PTRACE_SEIZE, config.pid, NULL, NULL) == -1) {
        fprintf(stderr, "Error: cannot seize process %d: %s\n", config.pid,
                strerror(errno));
        return ERROR;
    }

    // from here on the target is ours, so every exit has to detach it again
    if (ptrace(PTRACE_INTERRUPT, config.pid, NULL, NULL) == -1) { // stop tracee
        perror("Error: cannot interrupt the target process");
        goto detach;
    }

    if (waitpid(config.pid, &status, 0) == -1) {
        perror("Error: waiting for the target to stop failed");
        goto detach;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Error: process %d did not stop for the dump\n",
                config.pid);
        goto detach;
    }

    //-----------------------------------------------------------------------------
    // Info: the whole snapshot goes into a single file (later the path will
    // be specified) here the process is freezed

    // virtual folders important to dump
    // /proc/pid/mem        - physical memory areas
    // /proc/pid/maps       - areas important to save from mem
    // /proc/pid/exe        - path to executable program

    // 1.
    if (read_regs(config.pid, &regs) != OK)
        goto detach;
    // 2.
    if (read_exe_path(config.pid, exe_path, &exe_path_len) != OK)
        goto detach;
    // 3. the whole table is collected before any memory is read, so the
    // snapshot layout is known up front
    if (collect_vmas(config.pid, &vmas, &vma_count, &path_pool,
                     &path_pool_size, kernel_maps, &kernel_map_count) != OK)
        goto detach;
    // 4.
    if (write_snapshot(config.pid, &regs, exe_path, exe_path_len, vmas,
                       vma_count, path_pool, path_pool_size, kernel_maps,
                       kernel_map_count) != OK)
        goto detach;

    result = OK;

detach:
    free(vmas);
    free(path_pool);

    // waking the process
    if (ptrace(PTRACE_DETACH, config.pid, NULL, NULL) == -1) {
        perror("Error: cannot detach from the target process");
        result = ERROR;
    }

    return result;
}

static int read_regs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
        perror("Error: cannot read the registers of the target");
        return ERROR;
    }
    return OK;
}

static int read_exe_path(pid_t pid, char exe_path[PATH_MAX],
                         uint32_t *exe_path_len) {
    char process_path[64];
    snprintf(process_path, sizeof(process_path), "/proc/%d/exe", pid);

    // read path from /proc/pid/exe symbolic link
    ssize_t len = readlink(process_path, exe_path, PATH_MAX - 1);

    if (len < 0) {
        perror("Error: cannot read exe path");
        return ERROR;
    }
    if (len <= MIN_LEN_PATH) {
        fprintf(stderr, "Error: exe path of process %d is empty\n", pid);
        return ERROR;
    }

    exe_path[len] = '\0';
    *exe_path_len = (uint32_t)len;
    return OK;
}

static int collect_vmas(pid_t pid, vma_descriptor_t **out_vmas,
                        uint32_t *out_count, char **out_pool,
                        uint64_t *out_pool_size, kernel_map_t *kernel_maps,
                        uint32_t *out_kernel_map_count) {
    int result = ERROR;
    FILE *maps_file_handle = NULL;
    vma_descriptor_t *vmas = NULL;
    char *pool = NULL;
    uint32_t count = 0;
    uint32_t capacity = 0;
    uint64_t pool_size = 0;
    uint64_t pool_capacity = 0;
    uint32_t kernel_map_count = 0;

    char maps_line[MAPS_LINE_MAX];
    maps_line_t parsed;

    char process_path[64];
    snprintf(process_path, sizeof(process_path), "/proc/%d/maps", pid);
    maps_file_handle = fopen(process_path, "r");
    if (maps_file_handle == NULL) {
        perror("Error during opening the virtual file (proc/pid/maps)");
        goto cleanup;
    }

    //
    // 1. need to analyse maps
    // format is like this to parse
    // 08048000-08049000 r-xp 00000000 03:00 8312       /opt/test
    // 08049000-0804a000 rw-p 00001000 03:00 8312       /opt/test
    // 08050000-08051000 rw-p 00000000 00:00 0
    // the last field is optional - anonymous mappings carry no path
    //
    // 2. describe every area worth dumping
    //

    while (fgets(maps_line, sizeof(maps_line), maps_file_handle) != NULL) {

        if (!parse_maps_line(maps_line, &parsed)) {
            fprintf(stderr, "Warning: unparsable maps line skipped: %s",
                    maps_line);
            continue;
        }

        // the content is useless to copy but the address has to come back
        if (is_kernel_map(parsed.path)) {
            if (kernel_map_count == KSNAP_MAX_KERNEL_MAPS) {
                fprintf(stderr,
                        "Error: process %d has more than %d kernel mappings\n",
                        pid, KSNAP_MAX_KERNEL_MAPS);
                goto cleanup;
            }

            kernel_map_t *kernel_map = &kernel_maps[kernel_map_count];
            size_t name_len = strlen(parsed.path);

            // a truncated name would silently fail to match on restore
            if (name_len >= sizeof(kernel_map->name)) {
                fprintf(stderr, "Error: kernel mapping name too long: %s\n",
                        parsed.path);
                goto cleanup;
            }

            memset(kernel_map, 0, sizeof(*kernel_map));
            kernel_map->start_address = parsed.start;
            kernel_map->size = parsed.end - parsed.start;
            memcpy(kernel_map->name, parsed.path, name_len + 1);
            kernel_map_count++;
            continue;
        }

        if (parsed.privileges[0] != 'r')
            continue; // segment must be readable
        if (parsed.privileges[3] != 'p')
            continue; // segment memory must be private

        if (!is_dumpable_path(parsed.path))
            continue; // kernel owned pseudo mapping

        if (count == capacity) {
            uint32_t new_capacity =
                (capacity == 0) ? VMA_TABLE_INITIAL_CAPACITY : capacity * 2;
            vma_descriptor_t *grown =
                realloc(vmas, (size_t)new_capacity * sizeof(*grown));
            if (grown == NULL) {
                perror("Error: out of memory for the vma table");
                goto cleanup;
            }
            vmas = grown;
            capacity = new_capacity;
        }

        uint64_t path_len = strlen(parsed.path);
        uint64_t path_offset = 0;

        if (path_len > 0) {
            // paths are stored NUL terminated so a reader can use the pool
            // in place instead of copying out of it
            uint64_t needed = pool_size + path_len + 1;
            if (needed > pool_capacity) {
                uint64_t new_capacity = (pool_capacity == 0)
                                            ? PATH_POOL_INITIAL_CAPACITY
                                            : pool_capacity * 2;
                while (new_capacity < needed)
                    new_capacity *= 2;

                char *grown = realloc(pool, new_capacity);
                if (grown == NULL) {
                    perror("Error: out of memory for the path pool");
                    goto cleanup;
                }
                pool = grown;
                pool_capacity = new_capacity;
            }

            path_offset = pool_size;
            memcpy(pool + pool_size, parsed.path, path_len + 1);
            pool_size += path_len + 1;
        }

        vma_descriptor_t *vma = &vmas[count];
        vma->start_address = parsed.start;
        vma->size = parsed.end - parsed.start;
        vma->file_offset = parsed.file_offset;
        vma->data_offset = 0; // assigned once the snapshot layout is known
        vma->prot = perms_to_prot(parsed.privileges);
        vma->map_flags = perms_to_map_flags(parsed.privileges);
        vma->path_offset = (uint32_t)path_offset;
        vma->path_len = (uint32_t)path_len;
        count++;
    }

    if (ferror(maps_file_handle)) {
        perror("Read operation failure (proc/pid/maps)");
        goto cleanup;
    }

    if (count == 0) {
        fprintf(stderr, "Error: no dumpable mapping found for process %d\n",
                pid);
        goto cleanup;
    }

    *out_vmas = vmas;
    *out_count = count;
    *out_pool = pool;
    *out_pool_size = pool_size;
    *out_kernel_map_count = kernel_map_count;
    vmas = NULL; // ownership moved to the caller
    pool = NULL;
    result = OK;

cleanup:
    if (maps_file_handle != NULL)
        fclose(maps_file_handle);
    free(vmas);
    free(pool);
    return result;
}

static int write_snapshot(pid_t pid, const struct user_regs_struct *regs,
                          const char *exe_path, uint32_t exe_path_len,
                          vma_descriptor_t *vmas, uint32_t vma_count,
                          const char *pool, uint64_t pool_size,
                          const kernel_map_t *kernel_maps,
                          uint32_t kernel_map_count) {
    int result = ERROR;
    FILE *snapshot_handle = NULL;
    int mem_file_handle = -1;

    ksnap_dump_header_t header;
    char buff[PAGE_SIZE]; // 4096
    uint64_t payload_offset;
    long position;

    // ---------------------------
    // for read /proc/pid/mem
    char mem_process_path[PATH_MAX];
    snprintf(mem_process_path, sizeof(mem_process_path), "/proc/%d/mem", pid);
    mem_file_handle = open(mem_process_path, O_RDONLY); // open for reading only
    if (mem_file_handle == -1) {
        perror("Error during opening the virtual file (proc/pid/mem)");
        goto cleanup;
    }
    // ---------------------------

    snapshot_handle = fopen(KSNAP_SNAPSHOT_PATH, "wb");
    if (snapshot_handle == NULL) {
        perror("Error during opening the snapshot file");
        goto cleanup;
    }

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, KSNAP_MAGIC, KSNAP_MAGIC_LEN);
    header.version = KSNAP_FORMAT_VERSION;
    header.vma_count = vma_count;
    header.vma_table_offset = sizeof(header);
    header.path_pool_offset =
        header.vma_table_offset + (uint64_t)vma_count * sizeof(*vmas);
    header.path_pool_size = pool_size;
    header.data_offset = header.path_pool_offset + pool_size;
    header.exe_path_len = exe_path_len;
    memcpy(header.exe_path, exe_path, exe_path_len);
    header.kernel_map_count = kernel_map_count;
    memcpy(header.kernel_maps, kernel_maps,
           kernel_map_count * sizeof(*kernel_maps));
    header.regs = *regs;

    // payloads are streamed in table order right after the pool
    payload_offset = header.data_offset;
    for (uint32_t i = 0; i < vma_count; i++) {
        vmas[i].data_offset = payload_offset;
        payload_offset += vmas[i].size;
    }

    if (fwrite(&header, sizeof(header), 1, snapshot_handle) != 1) {
        perror("Write operation failure (snapshot header)");
        goto cleanup;
    }

    if (fwrite(vmas, sizeof(*vmas), vma_count, snapshot_handle) != vma_count) {
        perror("Write operation failure (snapshot vma table)");
        goto cleanup;
    }

    if (pool_size > 0 &&
        fwrite(pool, 1, pool_size, snapshot_handle) != pool_size) {
        perror("Write operation failure (snapshot path pool)");
        goto cleanup;
    }

    // the descriptors already promise where each payload lands, so the file
    // position has to agree before a single byte of memory is written
    position = ftell(snapshot_handle);
    if (position < 0 || (uint64_t)position != header.data_offset) {
        fprintf(stderr,
                "Error: snapshot layout mismatch, at %ld but expected %" PRIu64
                "\n",
                position, header.data_offset);
        goto cleanup;
    }

    for (uint32_t i = 0; i < vma_count; i++) {
        if (write_vma_payload(snapshot_handle, mem_file_handle, &vmas[i],
                              buff) != OK) {
            fprintf(stderr,
                    "Error: failed on mapping 0x%" PRIx64 "-0x%" PRIx64 "\n",
                    vmas[i].start_address,
                    vmas[i].start_address + vmas[i].size);
            goto cleanup;
        }
    }

    result = OK;

cleanup:
    if (mem_file_handle != -1)
        close(mem_file_handle);

    // buffered payload data only reaches the disk on fclose, so a failure
    // here still means an incomplete dump
    if (snapshot_handle != NULL && fclose(snapshot_handle) != 0) {
        perror("Error during closing the snapshot file");
        result = ERROR;
    }

    return result;
}

static int write_vma_payload(FILE *snapshot_handle, int mem_vma_handle,
                             const vma_descriptor_t *vma, char buff[]) {
    // copy exact amount of bytes from start segment
    uint64_t curr_send = 0;

    while (curr_send < vma->size) {
        uint64_t bytes_size = vma->size - curr_send;
        if (bytes_size > PAGE_SIZE)
            bytes_size = PAGE_SIZE;

        uint64_t curr_address = vma->start_address + curr_send;
        ssize_t bytes_read =
            pread(mem_vma_handle, buff, bytes_size, curr_address);

        if (bytes_read < 0) {
            if (errno == EINTR)
                continue; // interrupted before reading, just retry
            fprintf(stderr,
                    "Error: cannot read %" PRIu64 " bytes at 0x%" PRIx64
                    " from the target: %s\n",
                    bytes_size, curr_address, strerror(errno));
            return ERROR;
        }

        // a mapping listed in maps must be fully readable, so a short read
        // means the layout changed under us and the dump cannot be trusted
        if (bytes_read == 0) {
            fprintf(stderr,
                    "Error: unexpected end of memory at 0x%" PRIx64 "\n",
                    curr_address);
            return ERROR;
        }

        if (fwrite(buff, 1, bytes_read, snapshot_handle) !=
            (size_t)bytes_read) {
            perror("Write operation failure (snapshot payload)");
            return ERROR;
        }

        curr_send += bytes_read;
    }
    return OK;
}

static bool is_dumpable_path(const char *maps_path) {
    if (maps_path[0] != '[')
        return true; // anonymous mapping or a regular file

    return strcmp(maps_path, "[heap]") == 0 ||
           strcmp(maps_path, "[stack]") == 0;
}

static uint32_t perms_to_prot(const char privileges[5]) {
    uint32_t prot = PROT_NONE;

    if (privileges[0] == 'r')
        prot |= PROT_READ;
    if (privileges[1] == 'w')
        prot |= PROT_WRITE;
    if (privileges[2] == 'x')
        prot |= PROT_EXEC;

    return prot;
}

static uint32_t perms_to_map_flags(const char privileges[5]) {
    return privileges[3] == 'p' ? MAP_PRIVATE : MAP_SHARED;
}
