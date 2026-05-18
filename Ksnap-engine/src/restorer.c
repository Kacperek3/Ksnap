#include "restorer.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define PARENT
#define CHILD 0

// private functions
static int spawn_traced_child(char *exe_path);
static int set_final_regs(pid_t pid);
// inject_mmap_syscall(pid, seg);
// restore_segment_data(mem_fd, src_file, seg);
// restore_regs(pid, path);
// ------

void restorer(ksnap_config_t config) {
    pid_t new_process = fork();
    if (new_process < 0) {
        perror("fork fail");
        return;
    } else if (new_process == CHILD) {
        // child process here
        spawn_traced_child("../save/exe.bin");
    } else
        PARENT {
            // parent process here
            int status;
            waitpid(new_process, &status, 0);
            if (WIFSTOPPED(status)) {

                // 1. need to open all dump files
                // 2. change current registers to those from file
                // 3. use nmap with syscalls to overwrite current memory
                // 4. wake up the child process

                //
                // https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
                // 0F05 - syscall opcode
                // rax - 9 means for mmap
                // rdi - base address of virtual memory
                // rsi - size of this memory segment
                // rdx - privilages
                // r10 - flags
                // r8 - fd
                // r9 - offset
                //

                int mem_new_process_file_handle;

                FILE *mem_file_handle;
                mem_file_handle = fopen("../save/mem.bin", "rb");
                if (mem_file_handle == NULL) {
                    perror("save/mem.bin file could't be opened");
                    return;
                }
                vma_segment_t seg;

                char buff[4096];
                char process_mem_path[PATH_MAX];
                snprintf(process_mem_path, sizeof(process_mem_path),
                         "/proc/%d/mem", new_process);
                mem_new_process_file_handle = open(process_mem_path, O_WRONLY);

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
                    unsigned long curr_read = 0;
                    unsigned long bytes_to_read_now = 4096;

                    while (curr_read < seg.segment_size) {

                        if (curr_read + 4096 > seg.segment_size) {
                            bytes_to_read_now = seg.segment_size - curr_read;
                        }

                        fread(buff, 1, bytes_to_read_now, mem_file_handle);

                        pwrite(mem_new_process_file_handle, buff,
                               bytes_to_read_now,
                               seg.start_segment_address + curr_read);

                        curr_read += bytes_to_read_now;
                    }
                }
                close(mem_new_process_file_handle);
                fclose(mem_file_handle);

                set_final_regs(new_process);
                ptrace(PTRACE_DETACH, new_process, NULL, NULL);
                waitpid(new_process, &status, 0);
            }
        }

    return;
}

static int spawn_traced_child(char *exe_path) {
    FILE *exe_file_handle;
    exe_file_handle = fopen(exe_path, "rb");
    if (exe_file_handle == NULL) {
        perror("Error during opening the file");
    }

    fseek(exe_file_handle, 0, SEEK_END);
    int exe_path_size = ftell(exe_file_handle);
    fseek(exe_file_handle, 0, SEEK_SET);

    fread(exe_path, sizeof(char), exe_path_size, exe_file_handle);
    exe_path[exe_path_size] = '\0';
    char *args[] = {exe_path, NULL};
    fclose(exe_file_handle);

    personality(ADDR_NO_RANDOMIZE);
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execv(exe_path, args);

    perror("execv failed");
    exit(0);
}

static int set_final_regs(pid_t pid) {

    FILE *regs_file_handle;
    regs_file_handle = fopen("../save/regs.bin", "rb");

    if (regs_file_handle == NULL) {
        perror("Error during opening the file");
        return ERROR;
    }

    struct user_regs_struct final_regs;
    fread(&final_regs, sizeof(struct user_regs_struct), 1, regs_file_handle);
    fclose(regs_file_handle);

    ptrace(PTRACE_SETREGS, pid, NULL, &final_regs);

    return OK;
}
