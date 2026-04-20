#include "parser/parser.h"
#include <stdbool.h>

int main(int argc, char **argv) {

<<<<<<< Updated upstream
    ksync_config_t config;
    ksync_status_t status;
    status = parse_arg(argc, argv, &config);

=======
    ksnap_config_t config;
    ksnap_status_t status;
    status = parse_arg(argc, argv, &config);
    if (!check_status(&status))
        return 0;
    printf("its good brother");
>>>>>>> Stashed changes
    /*
     *
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
