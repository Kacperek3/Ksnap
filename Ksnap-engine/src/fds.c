#include "fds.h"
#include "config.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// what readlink reports for a descriptor that has no file behind it
#define FD_SOCKET "socket:"
#define FD_PIPE "pipe:"
#define FD_ANON "anon_inode:"

// readlink appends this once the file behind the link has been unlinked
#define DELETED_SUFFIX " (deleted)"

static bool starts_with(const char *text, const char *prefix) {
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

fd_class_t classify_fd(pid_t pid, int fd, char path[PATH_MAX]) {
    path[0] = '\0';

    if (fd <= STDERR_FILENO)
        return FD_SKIP_STDIO;

    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/fd/%d", pid, fd);

    ssize_t len = readlink(link, path, PATH_MAX - 1);
    if (len < 0) {
        path[0] = '\0';
        return FD_UNREADABLE;
    }
    path[len] = '\0';

    if (starts_with(path, FD_SOCKET) || starts_with(path, FD_PIPE) ||
        starts_with(path, FD_ANON))
        return FD_SKIP_VOLATILE;

    // stat follows the magic link to the open file itself, so it answers even
    // when the path readlink printed is gone
    struct stat open_file;
    if (stat(link, &open_file) != 0)
        return FD_UNREADABLE;

    if (!S_ISREG(open_file.st_mode))
        return FD_SKIP_OTHER;

    // memfd and O_TMPFILE files land here too, they never had a name
    size_t suffix_len = sizeof(DELETED_SUFFIX) - 1;
    if ((size_t)len > suffix_len &&
        !strcmp(path + len - suffix_len, DELETED_SUFFIX))
        return FD_SKIP_UNREACHABLE;

    struct stat by_path;
    if (stat(path, &by_path) != 0 || by_path.st_dev != open_file.st_dev ||
        by_path.st_ino != open_file.st_ino)
        return FD_SKIP_UNREACHABLE;

    return FD_DUMP;
}

int read_fd_state(pid_t pid, int fd, uint64_t *position, uint32_t *flags) {
    char fdinfo_path[64];
    snprintf(fdinfo_path, sizeof(fdinfo_path), "/proc/%d/fdinfo/%d", pid, fd);

    FILE *fdinfo_handle = fopen(fdinfo_path, "r");
    if (fdinfo_handle == NULL) {
        perror("Error during opening the virtual file (proc/pid/fdinfo)");
        return ERROR;
    }

    //
    // format is like this to parse, flags are octal
    // pos:    1234
    // flags:  02100002
    // mnt_id: 31
    // ino:    1835123
    // only the first two matter, locks listed further down are not restored
    //
    bool has_position = false;
    bool has_flags = false;
    char line[256];

    while (fgets(line, sizeof(line), fdinfo_handle) != NULL) {
        if (sscanf(line, "pos: %" SCNu64, position) == 1)
            has_position = true;
        else if (sscanf(line, "flags: %" SCNo32, flags) == 1)
            has_flags = true;
    }

    fclose(fdinfo_handle);

    if (!has_position || !has_flags) {
        fprintf(stderr, "Error: %s holds no offset or no flags\n", fdinfo_path);
        return ERROR;
    }

    return OK;
}
