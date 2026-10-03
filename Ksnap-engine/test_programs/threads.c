// A deliberately multi threaded counter, used by test/test_check.sh to prove
// that Check refuses what the engine cannot handle: Dump seizes the main
// thread only (see PTRACE_SEIZE in src/dumper.c), so the other threads would
// keep running while memory is copied and the restore would bring back one
// thread out of two.
//
// Build with: make test_programs

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static void *tick(void *argument) {
    int *counter = (int *)argument;

    while (1) {
        (*counter)++;
        sleep(1);
    }

    return NULL;
}

int main(void) {
    pthread_t worker;
    int counter = 0;

    printf("threads pid: %d\n", getpid());
    fflush(stdout);

    if (pthread_create(&worker, NULL, tick, &counter) != 0) {
        fprintf(stderr, "cannot start the second thread\n");
        return 1;
    }

    for (int i = 0; i < 100; i++) {
        printf("%d\n", counter);
        fflush(stdout);
        sleep(1);
    }

    return 0;
}
