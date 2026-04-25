#include <sys/ptrace.h> // for ptrace

#include <sys/types.h>
#include <sys/wait.h> // for waitpid

#include <unistd.h> // for sleep()

#include "dumper.h"

void dump(ksnap_config_t config) {
    int status;

    ptrace(PTRACE_SEIZE, config.pid, NULL,
           NULL); // attach process to our program
    ptrace(PTRACE_INTERRUPT, config.pid, NULL, NULL); // stoping tracee

    waitpid(config.pid, &status, 0);
    printf("process should be stopped for 5 sec\n");

    sleep(5);

    printf("process unfreezing \n");
    ptrace(PTRACE_DETACH, config.pid, NULL, NULL);
}
