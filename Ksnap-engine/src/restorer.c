#define _GNU_SOURCE // for MREMAP_MAYMOVE and MREMAP_FIXED

#include "restorer.h"
#include "dump_format.h"
#include "maps.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define PARENT
#define CHILD 0

// private functions
static int read_snapshot_metadata(FILE *snapshot_handle,
                                  ksnap_dump_header_t *header,
                                  vma_descriptor_t **out_vmas);
static int restore_vma(pid_t pid, int mem_fd, FILE *snapshot_handle,
                       const vma_descriptor_t *vma, char buff[]);
static int restore_kernel_maps(pid_t pid, const ksnap_dump_header_t *header);
static int inject_mmap_syscall(pid_t pid, const vma_descriptor_t *vma);
static int spawn_traced_child(const char *exe_path);
static int set_final_regs(pid_t pid, const struct user_regs_struct *regs);
// ------

int restorer(ksnap_config_t config) {
    (void)config;

    int result = ERROR;
    ksnap_dump_header_t header;
    vma_descriptor_t *vmas = NULL;

    // read before the fork - the executable to run comes from the header
    FILE *snapshot_handle = fopen(KSNAP_SNAPSHOT_PATH, "rb");
    if (snapshot_handle == NULL) {
        perror("Error during opening the snapshot file");
        return ERROR;
    }

    if (read_snapshot_metadata(snapshot_handle, &header, &vmas) != OK) {
        fclose(snapshot_handle);
        return ERROR;
    }

    pid_t new_process = fork();
    if (new_process < 0) {
        perror("fork fail");
        free(vmas);
        fclose(snapshot_handle);
        return ERROR;
    } else if (new_process == CHILD) {
        // child process here
        // the snapshot must not leak into the restored process
        fclose(snapshot_handle);
        free(vmas);
        spawn_traced_child(header.exe_path);
    } else
        PARENT {
            // parent process here
            int status;
            waitpid(new_process, &status, 0);
            if (WIFSTOPPED(status)) {

                // 1. metadata is already loaded
                // 2. use mmap with syscalls to recreate every area
                // 3. copy the payload of each area into the child
                // 4. change current registers to those from the snapshot
                // 5. wake up the child process

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

                char buff[4096];
                char process_mem_path[PATH_MAX];
                snprintf(process_mem_path, sizeof(process_mem_path),
                         "/proc/%d/mem", new_process);
                mem_new_process_file_handle = open(process_mem_path, O_WRONLY);

                if (mem_new_process_file_handle == -1) {
                    perror("Error during opening the virtual file "
                           "(proc/pid/mem)");
                } else if (restore_kernel_maps(new_process, &header) != OK) {
                    close(mem_new_process_file_handle);
                    mem_new_process_file_handle = -1;
                } else {
                    result = OK;
                    for (uint32_t i = 0; i < header.vma_count; i++) {
                        if (restore_vma(
                                new_process, mem_new_process_file_handle,
                                snapshot_handle, &vmas[i], buff) != OK) {
                            fprintf(stderr,
                                    "Error: failed to restore mapping "
                                    "0x%" PRIx64 "\n",
                                    vmas[i].start_address);
                            result = ERROR;
                            break;
                        }
                    }
                    close(mem_new_process_file_handle);
                }

                if (set_final_regs(new_process, &header.regs) != OK)
                    result = ERROR;

                ptrace(PTRACE_DETACH, new_process, NULL, NULL);
                waitpid(new_process, &status, 0);
            } else {
                fprintf(stderr, "Error: the new process did not stop for the "
                                "restore\n");
            }
        }

    free(vmas);
    fclose(snapshot_handle);
    return result;
}

static int read_snapshot_metadata(FILE *snapshot_handle,
                                  ksnap_dump_header_t *header,
                                  vma_descriptor_t **out_vmas) {
    struct stat snapshot_stat;

    if (fread(header, sizeof(*header), 1, snapshot_handle) != 1) {
        fprintf(stderr, "Error: snapshot is too short to hold a header\n");
        return ERROR;
    }

    if (memcmp(header->magic, KSNAP_MAGIC, KSNAP_MAGIC_LEN) != 0) {
        fprintf(stderr, "Error: not a Ksnap snapshot\n");
        return ERROR;
    }

    if (header->version != KSNAP_FORMAT_VERSION) {
        fprintf(stderr,
                "Error: snapshot format version %u, this build understands "
                "%u\n",
                header->version, KSNAP_FORMAT_VERSION);
        return ERROR;
    }

    if (header->vma_count == 0) {
        fprintf(stderr, "Error: snapshot describes no mapping\n");
        return ERROR;
    }

    // a damaged file must not turn into a huge allocation
    if (fstat(fileno(snapshot_handle), &snapshot_stat) != 0) {
        perror("Error: cannot stat the snapshot file");
        return ERROR;
    }

    uint64_t table_size = (uint64_t)header->vma_count * sizeof(**out_vmas);
    if (header->vma_table_offset + table_size >
            (uint64_t)snapshot_stat.st_size ||
        header->data_offset > (uint64_t)snapshot_stat.st_size) {
        fprintf(stderr, "Error: snapshot is truncated\n");
        return ERROR;
    }

    vma_descriptor_t *vmas = malloc(table_size);
    if (vmas == NULL) {
        perror("Error: out of memory for the vma table");
        return ERROR;
    }

    if (fseek(snapshot_handle, (long)header->vma_table_offset, SEEK_SET) != 0 ||
        fread(vmas, sizeof(*vmas), header->vma_count, snapshot_handle) !=
            header->vma_count) {
        perror("Read operation failure (snapshot vma table)");
        free(vmas);
        return ERROR;
    }

    // a payload past the end of the file would write garbage into the child
    for (uint32_t i = 0; i < header->vma_count; i++) {
        if (vmas[i].data_offset + vmas[i].size >
            (uint64_t)snapshot_stat.st_size) {
            fprintf(stderr,
                    "Error: payload of mapping 0x%" PRIx64 " runs past the "
                    "end of the snapshot\n",
                    vmas[i].start_address);
            free(vmas);
            return ERROR;
        }
    }

    *out_vmas = vmas;
    return OK;
}

static int restore_vma(pid_t pid, int mem_fd, FILE *snapshot_handle,
                       const vma_descriptor_t *vma, char buff[]) {

    if (inject_mmap_syscall(pid, vma) != OK)
        return ERROR;

    //---------------------------------------------------------
    // here the memory will be write into new created segments
    //---------------------------------------------------------
    if (fseek(snapshot_handle, (long)vma->data_offset, SEEK_SET) != 0) {
        perror("Error: cannot seek to the payload of a mapping");
        return ERROR;
    }

    uint64_t curr_read = 0;

    while (curr_read < vma->size) {
        uint64_t bytes_to_read_now = vma->size - curr_read;
        if (bytes_to_read_now > 4096)
            bytes_to_read_now = 4096;

        if (fread(buff, 1, bytes_to_read_now, snapshot_handle) !=
            bytes_to_read_now) {
            perror("Read operation failure (snapshot payload)");
            return ERROR;
        }

        ssize_t written = pwrite(mem_fd, buff, bytes_to_read_now,
                                 vma->start_address + curr_read);
        if (written != (ssize_t)bytes_to_read_now) {
            perror("Write operation failure (proc/pid/mem)");
            return ERROR;
        }

        curr_read += bytes_to_read_now;
    }

    return OK;
}

// run one syscall inside the stopped child
// the two bytes at rip are swapped for a syscall opcode
// one instruction is single stepped then code and registers go back
// the return value of the syscall lands in *syscall_result
static int inject_syscall(pid_t pid, unsigned long long number,
                          unsigned long long arg1, unsigned long long arg2,
                          unsigned long long arg3, unsigned long long arg4,
                          unsigned long long arg5, unsigned long long arg6,
                          unsigned long long *syscall_result) {
    struct user_regs_struct saved_regs;
    struct user_regs_struct work_regs;
    struct user_regs_struct after_regs;
    int status;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) == -1) {
        perror("Error: cannot read the registers of the child");
        return ERROR;
    }

    work_regs = saved_regs;
    work_regs.rax = number;
    work_regs.rdi = arg1;
    work_regs.rsi = arg2;
    work_regs.rdx = arg3;
    work_regs.r10 = arg4;
    work_regs.r8 = arg5;
    work_regs.r9 = arg6;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &work_regs) == -1) {
        perror("Error: cannot set up the injected syscall");
        return ERROR;
    }

    // save current instruction
    errno = 0;
    unsigned long long original_code =
        ptrace(PTRACE_PEEKTEXT, pid, (void *)(saved_regs.rip), NULL);
    if (original_code == (unsigned long long)-1 && errno != 0) {
        perror("Error: cannot read the code at the injection site");
        return ERROR;
    }

    long syscall_code = (original_code & 0xFFFFFFFFFFFF0000) | 0x050F;
    if (ptrace(PTRACE_POKETEXT, pid, (void *)(saved_regs.rip),
               (void *)(syscall_code)) == -1) {
        perror("Error: cannot plant the syscall opcode");
        return ERROR;
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) { // run syscall
        perror("Error: cannot single step the injected syscall");
        return ERROR;
    }

    if (waitpid(pid, &status, 0) == -1) {
        perror("Error: waiting for the injected syscall failed");
        return ERROR;
    }

    if (ptrace(PTRACE_GETREGS, pid, NULL, &after_regs) == -1) {
        perror("Error: cannot read the result of the injected syscall");
        return ERROR;
    }

    // set rip register and instruction back
    ptrace(PTRACE_POKETEXT, pid, (void *)(saved_regs.rip),
           (void *)(original_code));
    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) == -1) {
        perror("Error: cannot restore the registers after the syscall");
        return ERROR;
    }

    *syscall_result = after_regs.rax;
    return OK;
}

// the kernel reports failures as -errno in rax
static bool syscall_failed(unsigned long long syscall_result) {
    return syscall_result >= (unsigned long long)-4095L;
}

static int inject_mmap_syscall(pid_t pid, const vma_descriptor_t *vma) {
    unsigned long long syscall_result;

    // TODO: the recorded vma->prot is what the mapping should end up with
    // but the injection site itself lives in one of these areas and has to
    // stay executable so the protections are applied in a later pass

    if (inject_syscall(pid, SYS_mmap, vma->start_address, vma->size,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                       (unsigned long long)-1, 0, &syscall_result) != OK)
        return ERROR;

    if (syscall_failed(syscall_result)) {
        fprintf(stderr, "Error: mmap of 0x%" PRIx64 " failed: %s\n",
                vma->start_address, strerror(-(long)syscall_result));
        return ERROR;
    }

    return OK;
}

// move the kernel mappings of the child back to the dumped addresses
// glibc keeps resolved vdso pointers in its own data which we restore
// so without this the first clock_gettime() jumps into an unmapped hole
// runs before the MAP_FIXED loop so no segment can land on the vdso first
static int restore_kernel_maps(pid_t pid, const ksnap_dump_header_t *header) {
    unsigned long child_lowest = ULONG_MAX;
    unsigned long child_highest = 0;
    unsigned long wanted_lowest = ULONG_MAX;
    unsigned long wanted_highest = 0;

    if (header->kernel_map_count == 0)
        return OK;

    for (uint32_t i = 0; i < header->kernel_map_count; i++) {
        const kernel_map_t *wanted = &header->kernel_maps[i];
        unsigned long child_start;
        unsigned long child_size;

        if (find_named_map(pid, wanted->name, &child_start, &child_size) !=
            OK) {
            fprintf(stderr, "Error: the new process has no %s mapping\n",
                    wanted->name);
            return ERROR;
        }

        if (child_size != wanted->size) {
            fprintf(stderr,
                    "Error: %s is %lu bytes here but %" PRIu64
                    " bytes in the snapshot, kernel mismatch\n",
                    wanted->name, child_size, wanted->size);
            return ERROR;
        }

        if (child_start < child_lowest)
            child_lowest = child_start;
        if (child_start + child_size > child_highest)
            child_highest = child_start + child_size;
        if (wanted->start_address < wanted_lowest)
            wanted_lowest = wanted->start_address;
        if (wanted->start_address + wanted->size > wanted_highest)
            wanted_highest = wanted->start_address + wanted->size;
    }

    // MREMAP_FIXED unmaps whatever sits at the destination
    // an overlap would need a two step move which is not implemented
    if (child_lowest < wanted_highest && wanted_lowest < child_highest) {
        fprintf(stderr,
                "Error: kernel mappings at 0x%lx overlap their target at "
                "0x%lx, a two step move would be needed\n",
                child_lowest, wanted_lowest);
        return ERROR;
    }

    for (uint32_t i = 0; i < header->kernel_map_count; i++) {
        const kernel_map_t *wanted = &header->kernel_maps[i];
        unsigned long child_start;
        unsigned long child_size;
        unsigned long long syscall_result;

        if (find_named_map(pid, wanted->name, &child_start, &child_size) != OK)
            return ERROR;

        if (child_start == wanted->start_address)
            continue; // already in place

        if (inject_syscall(pid, SYS_mremap, child_start, child_size,
                           wanted->size, MREMAP_MAYMOVE | MREMAP_FIXED,
                           wanted->start_address, 0, &syscall_result) != OK)
            return ERROR;

        if (syscall_failed(syscall_result)) {
            fprintf(stderr,
                    "Error: cannot move %s from 0x%lx to 0x%" PRIx64 ": %s\n",
                    wanted->name, child_start, wanted->start_address,
                    strerror(-(long)syscall_result));
            return ERROR;
        }
    }

    return OK;
}

static int spawn_traced_child(const char *exe_path) {
    // the path comes straight out of the snapshot header which is already
    // NUL terminated so  it only has to be copied into a writable argv
    char argv0[PATH_MAX];
    snprintf(argv0, sizeof(argv0), "%s", exe_path);

    char *args[] = {argv0, NULL};

    personality(ADDR_NO_RANDOMIZE);
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execv(argv0, args);

    perror("execv failed");
    exit(EXIT_FAILURE);
}

static int set_final_regs(pid_t pid, const struct user_regs_struct *regs) {
    struct user_regs_struct final_regs = *regs;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &final_regs) == -1) {
        perror("Error: cannot restore the registers of the child");
        return ERROR;
    }

    return OK;
}
