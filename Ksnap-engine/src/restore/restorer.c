#include "restorer.h"
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct vma_segment_t {
    unsigned long start_segment_address;
    unsigned long segment_size;
} vma_segment_t;

void restorer(ksnap_config_t config) {
    printf("parent process \n");
    pid_t new_process = fork();
    if (new_process < 0) {
        perror("fork fail");
        return;
    } else if (new_process == 0) {
        // child process here
        char exe_path[PATH_MAX];
        FILE *exe_file_handle;
        exe_file_handle = fopen("save/exe.bin", "rb");
        if (exe_file_handle == NULL) {
            perror("error during open file\n");
        }

        fseek(exe_file_handle, 0, SEEK_END);
        int exe_path_size = ftell(exe_file_handle);
        fseek(exe_file_handle, 0, SEEK_SET);

        fread(exe_path, sizeof(char), exe_path_size, exe_file_handle);
        exe_path[exe_path_size] = '\0';
        char *args[] = {exe_path, NULL};
        fclose(exe_file_handle);

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(exe_path, args);

        perror("execv failed");
        exit(0);
    } else {
        // parent process here
        int status;
        waitpid(new_process, &status, 0);
        if (WIFSTOPPED(status)) {

            // 1. need to open all dump files
            // 2. change current registers to those from file
            // 3. use nmap with syscalls to overwrite current memory
            // 4. wake up the child process

            /* open a regs dump file
            FILE *regs_file_handle;
            regs_file_handle = fopen("save/regs.bin", "rb");
            struct user_regs_struct regs;
            fread(&regs, sizeof(struct user_regs_struct), 1, regs_file_handle);
            fclose(regs_file_handle);
            */

            //
            // 0F05 - syscall opcode
            // rax - 9 means for mmap
            // rdi - base address of virtual memory
            // rsi - size of this memory segment
            // rdx - privilages
            // r10 - flags
            // r8 - fd
            // r9 - offset
            //

            FILE *mem_file_handle;
            mem_file_handle = fopen("save/mem.bin", "rb");
            if (mem_file_handle == NULL) {
                perror("save/mem.bin file could't be opened");
                return;
            }
            vma_segment_t seg;

            while (fread(&seg, sizeof(seg), 1, mem_file_handle) == 1) {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, new_process, NULL, &regs);
                unsigned long long curr_rip_addres =
                    regs.rip; // save address memory of curr instruction

                regs.rax = 9;
                regs.rdi = seg.start_segment_address;
                regs.rsi = seg.segment_size;
                regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
                regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
                regs.r8 = -1;
                regs.r9 = 0;

                ptrace(PTRACE_SETREGS, new_process, NULL, &regs);
                // save current instruction
                unsigned long long original_code = ptrace(
                    PTRACE_PEEKTEXT, new_process, (void *)(regs.rip), NULL);

                long syscall_code =
                    (original_code & 0xFFFFFFFFFFFF0000) | 0x050F;
                ptrace(PTRACE_POKETEXT, new_process, (void *)(regs.rip),
                       (void *)(syscall_code));
                ptrace(PTRACE_SINGLESTEP, new_process, NULL,
                       NULL); // run syscall

                waitpid(new_process, &status, 0);

                // set rip register and instruction back
                ptrace(PTRACE_POKETEXT, new_process, (void *)(regs.rip),
                       (void *)(original_code));
                regs.rip = curr_rip_addres;
                ptrace(PTRACE_SETREGS, new_process, NULL, &regs);

                //---------------------------------------------------------
                // here the memory will be write into new created segments
                //---------------------------------------------------------
                //....
            }
        }
    }

    return;
}
