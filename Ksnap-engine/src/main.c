#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DUMPER_LEN (sizeof("DUMP") - 1)
#define RESTORER_LEN (sizeof("RESTOR") - 1)

int main(int argc, char **argv) {

    int opt;
    int pid;
    while ((opt = getopt(argc, argv, "m:p:hn")) != -1) {

        switch (opt) {
        case 'm':
            if (!strncmp(optarg, "Dump", DUMPER_LEN)) {
                printf("Dump chosen");
                // Dumper init can be here
            } else if (!strncmp(optarg, "Restore", RESTORER_LEN)) {
                printf("Restor chosen");
                // Restorer init can be here
            } else {
                printf("Wrong mode chosen");
            }
            break;

        case 'p':
            pid = atoi(optarg);
            printf("pid is: %d\n", pid);
            break;

        case 'h':
            printf("h flag added\n");
            break;

        case 'n':
            printf("n flag added\n");
            break;
        }
    }
    /*
        // when we got 0 arguments - we exiting program
        if (argc == MODE_NOT_SPECIFIED) {
            printf("\n----------------------------------- \n");
            printf("|    Program requires 2 parameters  |\n");
            printf("-----------------------------------\n");
            printf("\nSee Ksync --help for more information \n\n");
            return 0;
        }

        // when we got above 3 arguments - we exit program
        if (argc > MAX_PARAMS) {
            printf("\n----------------------------------- \n");
            printf("|    Program requires 2 parameters  |\n");
            printf("-----------------------------------\n");
            printf("\nSee Ksync --help for more information \n\n");
            return 0;
        }

        if (!strncmp(argv[1], "Dumper", DUMPER_LEN)) {
            int pid;
            printf("pid is %d", pid);
        }
    */
    return 0;
}
