#ifndef FDS_H
#define FDS_H

#include <linux/limits.h>
#include <stdint.h>
#include <sys/types.h>

// what the engine does with one open descriptor. Dump and Check both decide
// through classify_fd, the same way classify_maps_line serves the mappings, so
// Check cannot promise a descriptor the dump would leave behind.
typedef enum {
    FD_DUMP,             // regular file reachable by its path, reopened
    FD_SKIP_STDIO,       // 0, 1 and 2, the restored process gets the engine's
    FD_SKIP_VOLATILE,    // socket, pipe or anon inode, nothing to reopen
    FD_SKIP_UNREACHABLE, // regular file its path no longer leads to
    FD_SKIP_OTHER,       // device, directory and the rest, out of scope
    FD_UNREADABLE        // the link cannot be read, no access or closed
} fd_class_t;

// classify descriptor fd of process pid. The target of its /proc link lands in
// path, which is what the restore reopens for FD_DUMP. It stays empty for
// FD_SKIP_STDIO and FD_UNREADABLE.
fd_class_t classify_fd(pid_t pid, int fd, char path[PATH_MAX]);

// offset and O_* flags of one descriptor, out of /proc/<pid>/fdinfo/<fd>. The
// flags carry O_CLOEXEC when the descriptor has it. Returns OK or ERROR.
int read_fd_state(pid_t pid, int fd, uint64_t *position, uint32_t *flags);

#endif // FDS_H
