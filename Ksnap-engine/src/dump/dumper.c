#include <sys/ptrace.h> // for ptrace
#include <sys/user.h>   // for user_regs_struct

#include <sys/types.h>
#include <sys/wait.h> // for waitpid

#include <unistd.h> // for sleep()

#include "dumper.h"

void dump(ksnap_config_t config) {
    int status;
    struct user_regs_struct regs;

    ptrace(PTRACE_SEIZE, config.pid, NULL,
           NULL); // attach process to our program
    ptrace(PTRACE_INTERRUPT, config.pid, NULL, NULL); // stoping tracee

    waitpid(config.pid, &status, 0);
    ptrace(PTRACE_GETREGS, config.pid, NULL, &regs);

    FILE *file_handle;
    file_handle = fopen("save/regs.bin", "wb+");
    if (file_handle == NULL) {
        // handle it later
        printf("problem here \n");
        return;
    }

    int flag = fwrite(&regs, sizeof(struct user_regs_struct), 1, file_handle);

    if (!flag) {
        printf("write operation failure");
    } else {
        printf("write operation succesfully");
    }

    fclose(file_handle);
}
