
#include "config.h"
#include "dump/dumper.h"
#include "parser/parser.h"
#include <stdbool.h>

int main(int argc, char **argv) {

    ksnap_config_t config;
    ksnap_status_t status;
    status = parse_arg(argc, argv, &config);
    if (!check_status(&status))
        return EXIT;

    dump(config);
    return 0;
}
