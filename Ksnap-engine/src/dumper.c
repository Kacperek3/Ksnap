#include <stddef.h>
#include <stdio.h>
#include <sys/ptrace.h> // for ptrace
#include <sys/user.h>   // for user_regs_struct

#include <sys/types.h>
#include <sys/wait.h> // for waitpid

#include <dirent.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "dumper.h"
#include <fcntl.h>

#define MAPS_PATH_WIDTH "4095"
_Static_assert(PATH_MAX == 4096, "MAPS_PATH_WIDTH must be PATH_MAX - 1");

// private main functions
static int dump_regs(pid_t pid, char *out_path);
static int dump_exe_path(pid_t pid, char *out_path);
static int dump_memory(pid_t pid, char *out_path);
//
static int save_to_mem_bin(FILE *mem_dump_handle, int mem_vma_handle,
                           vma_segment_t seg, char buff[]);
static bool parse_maps_line(const char *maps_line, vma_segment_t *seg,
                            char privileges[5], char maps_path[PATH_MAX]);
static bool is_dumpable_path(const char *maps_path);

int dump(ksnap_config_t config) {
    int status;
    int result = ERROR;

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
    // Info: right now all of the dumped bytes are located in .../save/ path
    // (later the path will be specified) here the process is freezed

    // virtual folders important to dump
    // /proc/pid/mem        - physical memory areas
    // /proc/pid/maps       - areas important to save from mem
    // /proc/pid/exe        - path to executable program

    // 1.
    if (dump_regs(config.pid, config.output_dir) != OK)
        goto detach;
    // 2.
    if (dump_exe_path(config.pid, config.output_dir) != OK)
        goto detach;
    // 3.
    if (dump_memory(config.pid, config.output_dir) != OK)
        goto detach;

    result = OK;

detach:
    // waking the process
    if (ptrace(PTRACE_DETACH, config.pid, NULL, NULL) == -1) {
        perror("Error: cannot detach from the target process");
        result = ERROR;
    }

    return result;
}

static int dump_regs(pid_t pid, char *out_path) {
    //-----------------------------------------------
    // 1. Saving registers to file save/regs.bin
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) { // save regs
        perror("Error: cannot read the registers of the target");
        return ERROR;
    }

    FILE *file_handle;

    file_handle = fopen("../save/regs.bin", "wb+");
    if (file_handle == NULL) {
        // handle it later
        perror("Error during opening the file(save/regs.bin)");
        return ERROR;
    }

    if (fwrite(&regs, sizeof(struct user_regs_struct), 1, file_handle) != 1) {
        perror("Write operation failure (save/regs.bin)");
        fclose(file_handle);
        return ERROR;
    }

    // close connection to save/regs.bin
    if (fclose(file_handle) != 0) {
        perror("Error during closing the file (save/regs.bin)");
        return ERROR;
    }
    // -----------------------------------------------
    return OK;
}

static int dump_exe_path(pid_t pid, char *out_path) {
    //------------------------------------------------
    // 2. Saving path to executable into save/exe.bin
    char process_path[64];
    char target_path[PATH_MAX];
    snprintf(process_path, sizeof(process_path), "/proc/%d/exe", pid);
    int len = readlink(process_path, target_path,
                       sizeof(target_path) -
                           1); // read path from /proc/pid/exe symbolic link

    if (len < 0) {
        perror("Error: cannot read exe path");
        return ERROR;
    }
    if (len <= MIN_LEN_PATH) {
        fprintf(stderr, "Error: exe path of process %d is empty\n", pid);
        return ERROR;
    }
    target_path[len] = '\0';

    FILE *file_handle = fopen("../save/exe.bin", "wb+");
    if (file_handle == NULL) {
        perror("Error during opening the file (save/exe.bin)");
        return ERROR;
    }

    if (fwrite(target_path, len, 1, file_handle) != 1) {
        perror("Write operation failure (save/exe.bin)");
        fclose(file_handle);
        return ERROR;
    }

    if (fclose(file_handle) != 0) {
        perror("Error during closing the file (save/exe.bin)");
        return ERROR;
    }
    // --------------------------------------------------
    return OK;
}

static int dump_memory(pid_t pid, char *output_dir) {
    int result = ERROR;
    FILE *maps_file_handle = NULL;
    FILE *mem_dump_file_handle = NULL;
    int mem_file_handle = -1;

    char process_path[64];
    snprintf(process_path, sizeof(process_path), "/proc/%d/maps", pid);
    maps_file_handle = fopen(process_path, "r");
    if (maps_file_handle == NULL) {
        perror("Error during opening the virtual file (proc/pid/maps)");
        goto cleanup;
    }

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

    mem_dump_file_handle = fopen("../save/mem.bin", "wb");
    if (mem_dump_file_handle == NULL) {
        perror("Error during opening the file (save/mem.bin)");
        goto cleanup;
    }

    char privileges[5];
    vma_segment_t seg;
    char buff[PAGE_SIZE]; // 4096
    char maps_line[PATH_MAX + 128];
    char maps_path[PATH_MAX];

    //
    // 1. need to analyse maps
    // format is like this to parse
    // 08048000-08049000 r-xp 00000000 03:00 8312       /opt/test
    // 08049000-0804a000 rw-p 00001000 03:00 8312       /opt/test
    // 08050000-08051000 rw-p 00000000 00:00 0
    // the last field is optional - anonymous mappings carry no path
    //
    // 2. copy ares rw-p to file
    //

    while (fgets(maps_line, sizeof(maps_line), maps_file_handle) != NULL) {

        if (!parse_maps_line(maps_line, &seg, privileges, maps_path)) {
            fprintf(stderr, "Warning: unparsable maps line skipped: %s",
                    maps_line);
            continue;
        }

        if (privileges[0] != 'r')
            continue; // segment must be readable
        if (privileges[3] != 'p')
            continue; // segment memory must be private

        if (!is_dumpable_path(maps_path))
            continue; // kernel owned pseudo mapping

        if (save_to_mem_bin(mem_dump_file_handle, mem_file_handle, seg, buff) !=
            OK) {
            fprintf(stderr, "Error: failed on mapping %s", maps_line);
            goto cleanup;
        }
    }

    if (ferror(maps_file_handle)) {
        perror("Read operation failure (proc/pid/maps)");
        goto cleanup;
    }

    result = OK;

    // -----------------------------------------------
cleanup:
    if (mem_file_handle != -1)
        close(mem_file_handle);
    if (maps_file_handle != NULL)
        fclose(maps_file_handle);

    if (mem_dump_file_handle != NULL && fclose(mem_dump_file_handle) != 0) {
        perror("Error during closing the file (save/mem.bin)");
        result = ERROR;
    }

    return result;
}

static int save_to_mem_bin(FILE *mem_dump_handle, int mem_vma_handle,
                           vma_segment_t seg, char buff[]) {

    // save start and end addresses in mem.bin
    if (fwrite(&seg, sizeof(seg), 1, mem_dump_handle) != 1) {
        perror("Write operation failure (save/mem.bin segment header)");
        return ERROR;
    }

    // open /proc/pid/mem folder
    // 1. copy exact amount of bytes from start segment
    unsigned long curr_send = 0;

    while (curr_send < seg.segment_size) {
        unsigned long bytes_size = seg.segment_size - curr_send;
        if (bytes_size > PAGE_SIZE)
            bytes_size = PAGE_SIZE;

        unsigned long curr_address = seg.start_segment_address + curr_send;
        ssize_t bytes_read =
            pread(mem_vma_handle, buff, bytes_size, curr_address);

        if (bytes_read < 0) {
            if (errno == EINTR)
                continue; // interrupted before reading, just retry
            fprintf(stderr,
                    "Error: cannot read %lu bytes at 0x%lx from the target: "
                    "%s\n",
                    bytes_size, curr_address, strerror(errno));
            return ERROR;
        }

        if (bytes_read == 0) {
            fprintf(stderr, "Error: unexpected end of memory at 0x%lx\n",
                    curr_address);
            return ERROR;
        }

        // 2. write it into mem.bin
        if (fwrite(buff, 1, bytes_read, mem_dump_handle) !=
            (size_t)bytes_read) {
            perror("Write operation failure (save/mem.bin)");
            return ERROR;
        }

        curr_send += bytes_read;
    }
    return OK;
}

static bool parse_maps_line(const char *maps_line, vma_segment_t *seg,
                            char privileges[5], char maps_path[PATH_MAX]) {
    unsigned long finish_segment_address;

    privileges[0] = '\0';
    maps_path[0] = '\0';

    int parsed_fields =
        sscanf(maps_line, "%lx-%lx %4s %*s %*s %*s %" MAPS_PATH_WIDTH "s",
               &seg->start_segment_address, &finish_segment_address, privileges,
               maps_path);

    // address range plus privileges are mandatory, the path is not
    if (parsed_fields < 3)
        return false;

    if (strlen(privileges) != 4)
        return false;

    if (finish_segment_address <= seg->start_segment_address)
        return false;

    seg->segment_size = finish_segment_address - seg->start_segment_address;
    return true;
}

static bool is_dumpable_path(const char *maps_path) {
    if (maps_path[0] != '[')
        return true; // anonymous mapping or a regular file

    return strcmp(maps_path, "[heap]") == 0 ||
           strcmp(maps_path, "[stack]") == 0;
}
