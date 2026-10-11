#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "numbers.txt";

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror(path);
        return 1;
    }

    printf("file_counter pid: %d, writing to %s\n", getpid(), path);
    fflush(stdout);

    for (int number = 1; number <= 1000; number++) {
        char line[16];
        int len = snprintf(line, sizeof(line), "%d\n", number);
        off_t offset = lseek(fd, 0, SEEK_CUR);

        if (write(fd, line, len) != len) {
            perror("file_counter cannot write the next number");
            return 1;
        }

        printf("%d written at offset %ld\n", number, (long)offset);
        fflush(stdout);
        sleep(1);
    }

    return 0;
}
