/**
 * @file counter.c
 * @author Kacperek3
 * @date 24/03/2026
 * @brief Simple program that counts from 0 to 99 with 1 sec pause.
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

/**
 ** To speed up the PID search, it displays it at the beginning of the program
 * @return Return 0 when index reach 99.
 */

int main() {
    int own_pid = getpid();

    printf("-------------------------------\n");
    printf("|        PID is %d        | \n", own_pid);
    printf("-------------------------------\n\n");

    for (int i = 0; i < 100; i++) {
        printf("%d \n", i);
        fflush(stdout);
        sleep(1);
    }

    return 0;
}
