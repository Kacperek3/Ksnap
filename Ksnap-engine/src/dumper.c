#include <stddef.h>
#include <stdio.h>
#include <sys/ptrace.h> // for ptrace
#include <sys/user.h>   // for user_regs_struct

#include <sys/types.h>
#include <sys/wait.h> // for waitpid

#include <dirent.h>
#include <linux/limits.h>
#include <string.h>
#include <unistd.h>

#include "dumper.h"
#include <fcntl.h>

#define MIN_LEN_PATH 0

#define ERROR 0
#define SUCCESS 1

// private functions
static int dump_regs(pid_t pid, char *out_path);
static int dump_exe_path(pid_t pid, char *out_path);
static int dump_memory(pid_t pid, char *out_path);
//

void dump(ksnap_config_t config) {
    int status;

    ptrace(PTRACE_SEIZE, config.pid, NULL,
           NULL); // attach process to our program
    ptrace(PTRACE_INTERRUPT, config.pid, NULL, NULL); // stoping tracee

    waitpid(config.pid, &status, 0);

    //-----------------------------------------------------------------------------
    // Info: right now all of the dumped bytes are located in .../save/ path
    // (later the path will be specified) here the process is freezed

    // virtual folders important to dump
    // /proc/pid/mem        - physical memory areas
    // /proc/pid/maps       - areas important to save from mem
    // /proc/pid/exe        - path to executable program

    // 1.
    dump_regs(config.pid, config.output_dir);
    // 2.
    dump_exe_path(config.pid, config.output_dir);
    // 3.
    dump_memory(config.pid, config.output_dir);

    // waking the process
    ptrace(PTRACE_DETACH, config.pid, NULL, NULL);
}

static int dump_regs(pid_t pid, char *out_path) {
    //-----------------------------------------------
    // 1. Saving registers to file save/regs.bin
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs); // save regs
    FILE *file_handle;

    file_handle = fopen("../save/regs.bin", "wb+");
    if (file_handle == NULL) {
        // handle it later
        perror("Error during opening the file(save/regs.bin)");
        return ERROR;
    }

    if (fwrite(&regs, sizeof(struct user_regs_struct), 1, file_handle) ==
        ERROR) {
        perror("Write operation failure (save/regs.bin");
        return ERROR;
    }

    fclose(file_handle); // close connection to save/regs.bin
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

    if (len <= MIN_LEN_PATH) {
        perror("Error: cannot read exe path");
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
        return ERROR;
    }

    fclose(file_handle);
    // --------------------------------------------------
    return OK;
}

static int dump_memory(pid_t pid, char *output_dir) {
    char process_path[64];
    snprintf(process_path, sizeof(process_path), "/proc/%d/maps", pid);
    FILE *file_handle = fopen(process_path, "r");
    if (file_handle == NULL) {
        perror("Error during opening the virtual file (proc/pid/maps)");
        return ERROR;
    }

    // ---------------------------
    // for read /proc/pid/mem
    int mem_file_handle;
    char mem_process_path[PATH_MAX];
    snprintf(mem_process_path, sizeof(mem_process_path), "/proc/%d/mem", pid);
    mem_file_handle = open(mem_process_path, O_RDONLY); // open for reading only
    // ---------------------------

    FILE *mem_dump_file_handle;
    mem_dump_file_handle = fopen("../save/mem.bin", "wb");
    if (mem_dump_file_handle == NULL) {
        perror("Error during opening the file (save/mem.bin)");
        return ERROR;
    }

    char privileges[5];
    unsigned long finish_segment_address;
    vma_segment_t seg;
    char buff[PAGE_SIZE]; // 4096
    char maps_line[256];

    //
    // 1. need to analyse maps
    // format is like this to parse
    // 08048000-08049000 r-xp 00000000 03:00 8312       /opt/test
    // 08049000-0804a000 rw-p 00001000 03:00 8312       /opt/test
    //
    // 2. copy ares rw-p to file
    //

    while (fgets(maps_line, sizeof(maps_line), file_handle) != NULL) {

        sscanf(maps_line, "%lx-%lx %4s", &seg.start_segment_address,
               &finish_segment_address, privileges);

        seg.segment_size = finish_segment_address - seg.start_segment_address;

        if (!strcmp(privileges, "rw-p")) {
            // save start and end addresses in mem.bin
            fwrite(&seg, sizeof(seg), 1, mem_dump_file_handle);
            // open /proc/pid/mem folder
            // 1. copy exact amount of bytes from start segment
            unsigned long curr_send = 0;
            unsigned long bytes_size = 4096;

            while (curr_send < seg.segment_size) {
                if (curr_send + 4096 > seg.segment_size) {
                    bytes_size = seg.segment_size - curr_send;
                }
                pread(mem_file_handle, buff, bytes_size,
                      seg.start_segment_address + curr_send);
                // 2. write it into mem.bin
                fwrite(buff, bytes_size, 1, mem_dump_file_handle);
                curr_send += 4096;
            }
        }
    }

    close(mem_file_handle);
    fclose(file_handle);
    fclose(mem_dump_file_handle);

    // -----------------------------------------------
    return OK;
}
