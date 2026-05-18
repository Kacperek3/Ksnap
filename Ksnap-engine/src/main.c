
#include "config.h"
#include "dumper.h"
#include "parser.h"
#include "restorer.h"
#include <stdbool.h>

int main(int argc, char **argv) {

    ksnap_config_t config;
    ksnap_status_t status;
    status = parse_arg(argc, argv, &config);
    if (!check_status(&status))
        return EXIT;

    if (!strcmp(config.mode, "DUMP")) {
        dump(config);
    } else if (!strcmp(config.mode, "RESTORE")) {
        restorer(config);
    }
    return 0;
}
