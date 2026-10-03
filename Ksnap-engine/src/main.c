
#include "checker.h"
#include "config.h"
#include "dumper.h"
#include "parser.h"
#include "restorer.h"
#include <stdbool.h>
#include <stdlib.h>

int main(int argc, char **argv) {

    ksnap_config_t config;
    ksnap_status_t status;
    status = parse_arg(argc, argv, &config);
    if (!check_status(&status))
        return EXIT_FAILURE;

    if (!strcmp(config.mode, "DUMP")) {
        if (dump(config) != OK)
            return EXIT_FAILURE;
    } else if (!strcmp(config.mode, "RESTORE")) {
        if (restorer(config) != OK)
            return EXIT_FAILURE;
    } else if (!strcmp(config.mode, "CHECK")) {
        // Check has its own exit codes, a refused process is not a failure of
        // the tool, so the status is passed through untouched
        return check(config);
    }
    return EXIT_SUCCESS;
}
