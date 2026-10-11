#define _GNU_SOURCE // for close_range

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RECORD_SIZE 6

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    
    close_range(3, ~0U, 0);

    int input = open(argv[1], O_RDONLY);
    int twin = dup(input);
    int output = open(argv[2], O_WRONLY | O_APPEND | O_CREAT, 0644);
    int marked = open(argv[1], O_RDONLY | O_CLOEXEC);
    int lost[2];

    if (input == -1 || twin == -1 || output == -1 || marked == -1 ||
        pipe(lost) == -1) {
        perror("fd_reader cannot set up its descriptors");
        return 1;
    }

    printf("fd_reader pid: %d\n", getpid());
    fflush(stdout);

    for (int tick = 0; tick < 100; tick++) {
        char record[RECORD_SIZE + 1] = {0};
        int from = (tick % 2 == 0) ? input : twin;

        ssize_t got = read(from, record, RECORD_SIZE);
        if (got != RECORD_SIZE) {
            printf("BROKEN read through %d returned %zd: %s\n", from, got,
                   got < 0 ? strerror(errno) : "short record");
        } else if (write(output, record, RECORD_SIZE) != RECORD_SIZE) {
            printf("BROKEN write through %d: %s\n", output, strerror(errno));
        } else {
            int fd_flags = fcntl(marked, F_GETFD);
            printf("%d cloexec=%d\n", atoi(record),
                   fd_flags == -1 ? -1 : (fd_flags & FD_CLOEXEC) != 0);
        }

        fflush(stdout);
        sleep(1);
    }

    return 0;
}
