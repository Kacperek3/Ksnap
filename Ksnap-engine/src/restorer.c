#include "restorer.h"
#include "dump_format.h"
#include <fcntl.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <stdint.h>
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
static int inject_mmap_syscall(pid_t pid, const vma_descriptor_t *vma);
static int spawn_traced_child(const char *exe_path);
static int set_final_regs(pid_t pid, const struct user_regs_struct *regs);
// ------

int restorer(ksnap_config_t config) {
    (void)config;

    int result = ERROR;
    ksnap_dump_header_t header;
    vma_descriptor_t *vmas = NULL;

    // the snapshot has to be understood before anything is forked, because
    // the executable to run comes out of its header
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
        // child process here, the snapshot must not leak into the restored
        // process through an inherited descriptor
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

    // a truncated or damaged file must not turn into a huge allocation
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

    // every payload has to fit inside the file, otherwise the restore would
    // read past the end and write garbage into the child
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

static int inject_mmap_syscall(pid_t pid, const vma_descriptor_t *vma) {
    struct user_regs_struct regs;
    int status;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("Error: cannot read the registers of the child");
        return ERROR;
    }

    unsigned long long curr_rip_addres =
        regs.rip; // save address memory of curr instruction

    regs.rax = 9;
    regs.rdi = vma->start_address;
    regs.rsi = vma->size;
    // TODO: the recorded vma->prot is what the mapping should end up with
    // but the injection site itself lives in one of these areas and has to
    // stay executable so the protections are applied in a later pass

    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
    regs.r8 = -1;
    regs.r9 = 0;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    // save current instruction
    unsigned long long original_code =
        ptrace(PTRACE_PEEKTEXT, pid, (void *)(regs.rip), NULL);

    long syscall_code = (original_code & 0xFFFFFFFFFFFF0000) | 0x050F;
    ptrace(PTRACE_POKETEXT, pid, (void *)(regs.rip), (void *)(syscall_code));
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL); // run syscall

    waitpid(pid, &status, 0);

    // set rip register and instruction back
    ptrace(PTRACE_POKETEXT, pid, (void *)(regs.rip), (void *)(original_code));
    regs.rip = curr_rip_addres;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

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
