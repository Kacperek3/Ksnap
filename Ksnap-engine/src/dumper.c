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
#include <signal.h> // for kill
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h> // for PROT_* and MAP_*
#include <unistd.h>

#include "config.h"
#include "dump_format.h"
#include "dumper.h"
#include "fds.h"
#include "maps.h"
#include <ctype.h>
#include <elf.h> // for NT_X86_XSTATE
#include <fcntl.h>
#include <linux/kcmp.h>  // for KCMP_FILE
#include <sys/syscall.h> // for SYS_kcmp, glibc has no wrapper
#include <sys/uio.h>     // for struct iovec

#define VMA_TABLE_INITIAL_CAPACITY 64
#define FD_TABLE_INITIAL_CAPACITY 16
#define PATH_POOL_INITIAL_CAPACITY 4096

// the path strings of the snapshot, the vma table and the fd table both point
// into it by offset
typedef struct {
    char *data;
    uint64_t size;
    uint64_t capacity;
} path_pool_t;

// private main functions
static int read_regs(pid_t pid, struct user_regs_struct *regs);
static int read_xstate(pid_t pid, void **out_xstate, uint32_t *out_size);
static int read_exe_path(pid_t pid, char exe_path[PATH_MAX],
                         uint32_t *exe_path_len);
static int collect_vmas(pid_t pid, vma_descriptor_t **out_vmas,
                        uint32_t *out_count, path_pool_t *pool,
                        kernel_map_t *kernel_maps,
                        uint32_t *out_kernel_map_count);
static int collect_fds(pid_t pid, fd_descriptor_t **out_fds,
                       uint32_t *out_count, path_pool_t *pool);
static int write_snapshot(
    pid_t pid, const char *snapshot_path, const struct user_regs_struct *regs,
    const void *xstate, uint32_t xstate_size, const char *exe_path,
    uint32_t exe_path_len, vma_descriptor_t *vmas, uint32_t vma_count,
    const fd_descriptor_t *fds, uint32_t fd_count, const path_pool_t *pool,
    const kernel_map_t *kernel_maps, uint32_t kernel_map_count);
//
static int pool_append(path_pool_t *pool, const char *path,
                       uint32_t *out_offset);
static void find_shared_files(pid_t pid, fd_descriptor_t *fds, uint32_t count,
                              const path_pool_t *pool);
static int write_vma_payload(FILE *snapshot_handle, int mem_vma_handle,
                             const vma_descriptor_t *vma, char buff[]);

int dump(ksnap_config_t config) {
    int status;
    int result = ERROR;

    struct user_regs_struct regs;
    void *xstate = NULL;
    uint32_t xstate_size = 0;
    char exe_path[PATH_MAX];
    uint32_t exe_path_len = 0;
    vma_descriptor_t *vmas = NULL;
    uint32_t vma_count = 0;
    fd_descriptor_t *fds = NULL;
    uint32_t fd_count = 0;
    path_pool_t path_pool = {0};
    kernel_map_t kernel_maps[KSNAP_MAX_KERNEL_MAPS];
    uint32_t kernel_map_count = 0;
    char snapshot_path[PATH_MAX];

    // resolved before the target is touched, a bad path must not leave the
    // process frozen for nothing
    if (build_snapshot_path(&config, snapshot_path) != OK)
        return ERROR;

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
    // /proc/pid/fd         - open descriptors, fdinfo holds their offsets

    // 1.
    if (read_regs(config.pid, &regs) != OK)
        goto detach;
    // 1b. the general registers alone are not the whole CPU state, a process
    // stopped in the middle of a computation keeps live values in xmm/ymm and
    // its rounding mode in MXCSR
    if (read_xstate(config.pid, &xstate, &xstate_size) != OK)
        goto detach;
    // 2.
    if (read_exe_path(config.pid, exe_path, &exe_path_len) != OK)
        goto detach;
    // 3. the whole table is collected before any memory is read, so the
    // snapshot layout is known up front
    if (collect_vmas(config.pid, &vmas, &vma_count, &path_pool, kernel_maps,
                     &kernel_map_count) != OK)
        goto detach;
    // 3b. the regular files it has open, their paths join the same pool
    if (collect_fds(config.pid, &fds, &fd_count, &path_pool) != OK)
        goto detach;
    // 4.
    if (write_snapshot(config.pid, snapshot_path, &regs, xstate, xstate_size,
                       exe_path, exe_path_len, vmas, vma_count, fds, fd_count,
                       &path_pool, kernel_maps, kernel_map_count) != OK)
        goto detach;

    result = OK;

detach:
    free(xstate);
    free(vmas);
    free(fds);
    free(path_pool.data);

    // -k: the process is killed while it is still stopped by ptrace, so it
    // never executes a single instruction past the state in the snapshot.
    // Only a complete snapshot ends it, a failed dump releases it as usual.
    if (result == OK && config.kill_after_dump) {
        if (kill(config.pid, SIGKILL) == 0) {
            // the tracer is told about the death too, collect that notice
            waitpid(config.pid, &status, 0);
            printf("Process %d terminated after the snapshot\n", config.pid);
            return OK;
        }

        fprintf(stderr,
                "Error: the snapshot is saved, but process %d could not be "
                "terminated: %s\n",
                config.pid, strerror(errno));
        result = ERROR;
    }

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

// fpu dump
static int read_xstate(pid_t pid, void **out_xstate, uint32_t *out_size) {
    void *xstate = calloc(1, KSNAP_XSTATE_MAX_SIZE);
    if (xstate == NULL) {
        perror("Error: out of memory for the xstate");
        return ERROR;
    }

    struct iovec iov = {.iov_base = xstate, .iov_len = KSNAP_XSTATE_MAX_SIZE};

    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_X86_XSTATE, &iov) == -1) {
        perror("Error: cannot read the FPU/SSE/AVX state of the target");
        free(xstate);
        return ERROR;
    }

    // a full buffer could mean the area was cut short, restoring half of it
    // would be worse than refusing
    if (iov.iov_len < KSNAP_XSTATE_MIN_SIZE ||
        iov.iov_len >= KSNAP_XSTATE_MAX_SIZE) {
        fprintf(stderr, "Error: unexpected xstate size of %zu bytes\n",
                iov.iov_len);
        free(xstate);
        return ERROR;
    }

    *out_xstate = xstate;
    *out_size = (uint32_t)iov.iov_len;
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
                        uint32_t *out_count, path_pool_t *pool,
                        kernel_map_t *kernel_maps,
                        uint32_t *out_kernel_map_count) {
    int result = ERROR;
    FILE *maps_file_handle = NULL;
    vma_descriptor_t *vmas = NULL;
    uint32_t count = 0;
    uint32_t capacity = 0;
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

        vma_class_t vma_class = classify_maps_line(&parsed);

        if (vma_class == VMA_SKIP_UNREADABLE || vma_class == VMA_SKIP_SHARED ||
            vma_class == VMA_SKIP_PSEUDO)
            continue;

        if (vma_class == VMA_KERNEL) {
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
        uint32_t path_offset = 0;

        if (path_len > 0 && pool_append(pool, parsed.path, &path_offset) != OK)
            goto cleanup;

        vma_descriptor_t *vma = &vmas[count];
        vma->start_address = parsed.start;
        vma->size = parsed.end - parsed.start;
        vma->file_offset = parsed.file_offset;
        vma->data_offset = 0; // assigned once the snapshot layout is known
        vma->prot = perms_to_prot(parsed.privileges);
        vma->map_flags = perms_to_map_flags(parsed.privileges);
        vma->path_offset = path_offset;
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
    *out_kernel_map_count = kernel_map_count;
    vmas = NULL; // ownership moved to the caller
    result = OK;

cleanup:
    if (maps_file_handle != NULL)
        fclose(maps_file_handle);
    free(vmas);
    return result;
}

static int compare_fd_descriptors(const void *left, const void *right) {
    int32_t a = ((const fd_descriptor_t *)left)->fd;
    int32_t b = ((const fd_descriptor_t *)right)->fd;
    return (a > b) - (a < b);
}

static int collect_fds(pid_t pid, fd_descriptor_t **out_fds,
                       uint32_t *out_count, path_pool_t *pool) {
    int result = ERROR;
    DIR *fd_dir_handle = NULL;
    fd_descriptor_t *fds = NULL;
    uint32_t count = 0;
    uint32_t capacity = 0;
    char path[PATH_MAX];

    char process_path[64];
    snprintf(process_path, sizeof(process_path), "/proc/%d/fd", pid);
    fd_dir_handle = opendir(process_path);
    if (fd_dir_handle == NULL) {
        perror("Error during opening the virtual folder (proc/pid/fd)");
        goto cleanup;
    }

    struct dirent *entry;
    while ((entry = readdir(fd_dir_handle)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0]))
            continue;

        int fd = atoi(entry->d_name);
        fd_class_t fd_class = classify_fd(pid, fd, path);

        if (fd_class == FD_SKIP_STDIO)
            continue;

        // the target is stopped, so its descriptors cannot come and go
        if (fd_class == FD_UNREADABLE) {
            fprintf(stderr,
                    "Error: descriptor %d of process %d cannot be read\n", fd,
                    pid);
            goto cleanup;
        }

        // the restored process simply will not have it, Check reports that
        // before the dump as open_fds without a matching dumpable_fds
        if (fd_class != FD_DUMP) {
            fprintf(stderr, "Warning: descriptor %d (%s) is not carried over\n",
                    fd, path);
            continue;
        }

        if (count == capacity) {
            uint32_t new_capacity =
                (capacity == 0) ? FD_TABLE_INITIAL_CAPACITY : capacity * 2;
            fd_descriptor_t *grown =
                realloc(fds, (size_t)new_capacity * sizeof(*grown));
            if (grown == NULL) {
                perror("Error: out of memory for the fd table");
                goto cleanup;
            }
            fds = grown;
            capacity = new_capacity;
        }

        fd_descriptor_t *descriptor = &fds[count];
        memset(descriptor, 0, sizeof(*descriptor));
        descriptor->fd = fd;
        descriptor->dup_of = -1;
        descriptor->path_len = (uint32_t)strlen(path);

        if (read_fd_state(pid, fd, &descriptor->position, &descriptor->flags) !=
                OK ||
            pool_append(pool, path, &descriptor->path_offset) != OK)
            goto cleanup;

        count++;
    }

    // readdir promises no order, the restore wants the table sorted
    if (count > 1)
        qsort(fds, count, sizeof(*fds), compare_fd_descriptors);
    find_shared_files(pid, fds, count, pool);

    *out_fds = fds;
    *out_count = count;
    fds = NULL; // ownership moved to the caller
    result = OK;

cleanup:
    if (fd_dir_handle != NULL)
        closedir(fd_dir_handle);
    free(fds);
    return result;
}

// two descriptors made by dup() share one open file, and with it one offset.
// Reopening each by path would split them, so the later one is marked as a
// copy of the earlier one and the restore dup()s it instead of opening it.
static void find_shared_files(pid_t pid, fd_descriptor_t *fds, uint32_t count,
                              const path_pool_t *pool) {
    for (uint32_t i = 1; i < count; i++) {
        const char *path = pool->data + fds[i].path_offset;

        for (uint32_t j = 0; j < i; j++) {
            // a dup has the same path, which spares kcmp for nearly every pair
            if (fds[j].dup_of != -1 ||
                strcmp(path, pool->data + fds[j].path_offset) != 0)
                continue;

            long order =
                syscall(SYS_kcmp, pid, pid, KCMP_FILE, fds[j].fd, fds[i].fd);
            if (order == -1) {
                // every descriptor then gets an open file of its own, which
                // only a process relying on a shared offset would notice
                fprintf(stderr,
                        "Warning: cannot compare descriptors, a dup() will "
                        "come back as a separate open file: %s\n",
                        strerror(errno));
                return;
            }

            if (order == 0) {
                fds[i].dup_of = fds[j].fd;
                break;
            }
        }
    }
}

static int pool_append(path_pool_t *pool, const char *path,
                       uint32_t *out_offset) {
    uint64_t path_len = strlen(path);

    // paths are stored NUL terminated so a reader can use the pool in place
    // instead of copying out of it
    uint64_t needed = pool->size + path_len + 1;

    // descriptors keep the offset in 32 bits
    if (needed > UINT32_MAX) {
        fprintf(stderr, "Error: the path pool outgrew 4 GiB\n");
        return ERROR;
    }

    if (needed > pool->capacity) {
        uint64_t new_capacity = (pool->capacity == 0)
                                    ? PATH_POOL_INITIAL_CAPACITY
                                    : pool->capacity * 2;
        while (new_capacity < needed)
            new_capacity *= 2;

        char *grown = realloc(pool->data, new_capacity);
        if (grown == NULL) {
            perror("Error: out of memory for the path pool");
            return ERROR;
        }
        pool->data = grown;
        pool->capacity = new_capacity;
    }

    *out_offset = (uint32_t)pool->size;
    memcpy(pool->data + pool->size, path, path_len + 1);
    pool->size += path_len + 1;
    return OK;
}

static int write_snapshot(
    pid_t pid, const char *snapshot_path, const struct user_regs_struct *regs,
    const void *xstate, uint32_t xstate_size, const char *exe_path,
    uint32_t exe_path_len, vma_descriptor_t *vmas, uint32_t vma_count,
    const fd_descriptor_t *fds, uint32_t fd_count, const path_pool_t *pool,
    const kernel_map_t *kernel_maps, uint32_t kernel_map_count) {
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

    snapshot_handle = fopen(snapshot_path, "wb");
    if (snapshot_handle == NULL) {
        perror("Error during opening the snapshot file");
        goto cleanup;
    }

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, KSNAP_MAGIC, KSNAP_MAGIC_LEN);
    header.version = KSNAP_FORMAT_VERSION;
    header.vma_count = vma_count;
    header.vma_table_offset = sizeof(header);
    header.fd_count = fd_count;
    header.fd_table_offset =
        header.vma_table_offset + (uint64_t)vma_count * sizeof(*vmas);
    header.path_pool_offset =
        header.fd_table_offset + (uint64_t)fd_count * sizeof(*fds);
    header.path_pool_size = pool->size;
    header.xstate_offset = header.path_pool_offset + pool->size;
    header.xstate_size = xstate_size;
    header.data_offset = header.xstate_offset + xstate_size;
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

    if (fd_count > 0 &&
        fwrite(fds, sizeof(*fds), fd_count, snapshot_handle) != fd_count) {
        perror("Write operation failure (snapshot fd table)");
        goto cleanup;
    }

    if (pool->size > 0 &&
        fwrite(pool->data, 1, pool->size, snapshot_handle) != pool->size) {
        perror("Write operation failure (snapshot path pool)");
        goto cleanup;
    }

    if (fwrite(xstate, 1, xstate_size, snapshot_handle) != xstate_size) {
        perror("Write operation failure (snapshot xstate)");
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

    // a snapshot is only done once it is on the disk, not only in the page
    // cache. With -k it is about to become the only copy of the process.
    if (result == OK &&
        (fflush(snapshot_handle) != 0 || fsync(fileno(snapshot_handle)) != 0)) {
        perror("Error during flushing the snapshot file to disk");
        result = ERROR;
    }

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
