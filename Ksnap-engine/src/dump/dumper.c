#include <stdio.h>
#include <sys/ptrace.h> // for ptrace
#include <sys/user.h>   // for user_regs_struct

#include <sys/types.h>
#include <sys/wait.h> // for waitpid

#include <dirent.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dumper.h"

void dump(ksnap_config_t config) {
    int status;
    struct user_regs_struct regs;

    ptrace(PTRACE_SEIZE, config.pid, NULL,
           NULL); // attach process to our program
    ptrace(PTRACE_INTERRUPT, config.pid, NULL, NULL); // stoping tracee

    waitpid(config.pid, &status, 0);

    //-------------------------------------
    // here the process is freezed

    ptrace(PTRACE_GETREGS, config.pid, NULL, &regs);
    FILE *file_handle;

    file_handle = fopen("save/regs.bin", "wb+");
    if (file_handle == NULL) {
        // handle it later
        printf("error during opening the file(save/regs.bin) \n");
        return;
    }

    int flag = fwrite(&regs, sizeof(struct user_regs_struct), 1, file_handle);

    if (!flag) {
        printf("write operation failure");
    } else {
        printf("write regs succesfully \n");
    }
    fclose(file_handle); // close connection to save/regs.bin

    // folders important to dump/read
    // /proc/pid/mem        - physical memory areas
    // /proc/pid/maps       - areas important to save from mem
    // /proc/pid/exe        - path to executable program

    char process_path[64];
    char target_path[PATH_MAX];
    snprintf(process_path, sizeof(process_path), "/proc/%d/exe", config.pid);
    int len = readlink(process_path, target_path, sizeof(target_path) - 1);
    target_path[len] = '\0';

    file_handle = fopen("save/exe.bin", "wb+");
    if (file_handle == NULL) {
        printf("error during opening the file (save/exe.bin) \n");
        return;
    }

    flag = fwrite(target_path, len, 1, file_handle);

    if (!flag) {
        printf("write operation failure");
    } else {
        printf("write exe succesfully \n");
    }
    fclose(file_handle);

    //
    // 1. need to analyse maps
    // format is like this to parse
    // 08048000-08049000 r-xp 00000000 03:00 8312       /opt/test
    // 08049000-0804a000 rw-p 00001000 03:00 8312       /opt/test
    //
    // 2. copy ares rw-p to file
    //

    char maps_line[256];
    snprintf(process_path, sizeof(process_path), "/proc/%d/maps", config.pid);
    file_handle = fopen(process_path, "r");
    while (fgets(maps_line, sizeof(maps_line), file_handle) != NULL) {
        printf("%s\n", maps_line);
    }

    fclose(file_handle);
    ptrace(PTRACE_DETACH, config.pid, NULL, NULL); // waking the process
}
