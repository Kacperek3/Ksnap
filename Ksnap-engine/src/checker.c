#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "checker.h"
#include "config.h"
#include "dump_format.h"
#include "maps.h"

// a process cannot collect more than a handful of distinct problems
#define KSNAP_MAX_REASONS 8

#define COMM_LEN 64
#define DETAIL_LEN 160

// what readlink reports for a descriptor that has no file behind it
#define FD_SOCKET "socket:"
#define FD_PIPE "pipe:"
#define FD_ANON "anon_inode:"

// readlink appends this once the binary behind /proc/<pid>/exe is gone
#define DELETED_SUFFIX " (deleted)"

typedef struct {
    const char *code; // stable identifier, read by the panel
    char detail[DETAIL_LEN];
} check_reason_t;

typedef struct {
    pid_t pid;
    char comm[COMM_LEN];
    char state;
    int threads;
    int tracer_pid;
    int argc;
    int open_fds;     // descriptors besides 0, 1 and 2
    int volatile_fds; // of those, the ones with no file behind them
    int children;
    uid_t uid;
    uint64_t rss_kb;
    char exe_path[PATH_MAX];

    uint32_t dumpable_vmas;
    uint32_t kernel_maps;
    uint32_t shared_vmas;
    uint32_t device_vmas;
    uint64_t snapshot_bytes; // what the payload of the snapshot would weigh

    bool ptrace_probed;
    bool ptrace_ok;

    check_reason_t reasons[KSNAP_MAX_REASONS];
    uint32_t reason_count;
} check_report_t;

static int check_one(pid_t pid, bool probe);
static int check_all(void);

static void add_reason(check_report_t *report, const char *code,
                       const char *format, ...);
static int read_status_fields(pid_t pid, check_report_t *report);
static void read_cmdline_argc(pid_t pid, check_report_t *report);
static void probe_exe(pid_t pid, check_report_t *report);
static void scan_maps(pid_t pid, check_report_t *report);
static void scan_fds(pid_t pid, check_report_t *report);
static void count_children(pid_t pid, check_report_t *report);
static void probe_ptrace(pid_t pid, check_report_t *report);
static void print_report(const check_report_t *report);
static void print_json_string(const char *value);

int check(ksnap_config_t config) {
    // -p is optional here: one process when it is given, the whole /proc
    // otherwise, which is what the panel needs for its process list
    if (config.pid == -1)
        return check_all();

    // an explicit target is worth the ptrace probe, a sweep over every process
    // is not, it would touch hundreds of processes on every refresh
    return check_one(config.pid, true);
}

static int check_all(void) {
    DIR *proc_handle = opendir("/proc");
    if (proc_handle == NULL) {
        perror("Error during opening /proc");
        return KSNAP_CHECK_EXIT_ERROR;
    }

    pid_t self = getpid();
    struct dirent *entry;

    while ((entry = readdir(proc_handle)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0]))
            continue;

        pid_t pid = (pid_t)strtol(entry->d_name, NULL, 10);
        if (pid <= 0 || pid == self)
            continue;

        check_one(pid, false);
    }

    closedir(proc_handle);
    return KSNAP_CHECK_EXIT_DUMPABLE;
}

static int check_one(pid_t pid, bool probe) {
    check_report_t report;

    memset(&report, 0, sizeof(report));
    report.pid = pid;
    report.state = '?';

    if (read_status_fields(pid, &report) != OK) {
        print_report(&report);
        return KSNAP_CHECK_EXIT_BLOCKED;
    }

    read_cmdline_argc(pid, &report);

    // the cheap verdicts come first, so a process that is out of scope anyway
    // does not cost four more file reads during a sweep
    if (report.threads > 1)
        add_reason(&report, "multi_threaded",
                   "the dump seizes the main thread only, this process has %d",
                   report.threads);

    if (report.state == 'Z' || report.state == 'X')
        add_reason(&report, "zombie",
                   "the process is dead, there is no address space to copy");

    if (report.tracer_pid != 0)
        add_reason(&report, "already_traced",
                   "process %d is tracing it, ptrace allows one tracer",
                   report.tracer_pid);

    // no command line means no address space of its own
    if (report.argc == 0)
        add_reason(&report, "kernel_thread",
                   "kernel threads own no memory that could be snapshotted");

    if (report.reason_count > 0) {
        print_report(&report);
        return KSNAP_CHECK_EXIT_BLOCKED;
    }

    probe_exe(pid, &report);
    scan_maps(pid, &report);
    scan_fds(pid, &report);
    count_children(pid, &report);

    if (probe && report.reason_count == 0)
        probe_ptrace(pid, &report);

    print_report(&report);
    return report.reason_count == 0 ? KSNAP_CHECK_EXIT_DUMPABLE
                                    : KSNAP_CHECK_EXIT_BLOCKED;
}

static void add_reason(check_report_t *report, const char *code,
                       const char *format, ...) {
    if (report->reason_count == KSNAP_MAX_REASONS)
        return; // the first eight already explain enough

    check_reason_t *reason = &report->reasons[report->reason_count];
    reason->code = code;

    va_list args;
    va_start(args, format);
    vsnprintf(reason->detail, sizeof(reason->detail), format, args);
    va_end(args);

    report->reason_count++;
}

// one pass over /proc/<pid>/status, which carries everything the cheap rules
// need. The dumper never reads this file, so the thread count is new here.
static int read_status_fields(pid_t pid, check_report_t *report) {
    char status_path[64];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);

    FILE *status_handle = fopen(status_path, "r");
    if (status_handle == NULL) {
        if (errno == EACCES || errno == EPERM)
            add_reason(report, "not_inspectable",
                       "/proc/%d/status cannot be read, run the engine as root",
                       pid);
        else
            add_reason(report, "gone",
                       "the process disappeared while it was inspected");
        return ERROR;
    }

    char line[512];
    while (fgets(line, sizeof(line), status_handle) != NULL) {
        if (!strncmp(line, "Name:", 5))
            sscanf(line, "Name:\t%63[^\n]", report->comm);
        else if (!strncmp(line, "State:", 6))
            sscanf(line, "State:\t%c", &report->state);
        else if (!strncmp(line, "Uid:", 4))
            sscanf(line, "Uid:\t%u", &report->uid);
        else if (!strncmp(line, "Threads:", 8))
            sscanf(line, "Threads:\t%d", &report->threads);
        else if (!strncmp(line, "TracerPid:", 10))
            sscanf(line, "TracerPid:\t%d", &report->tracer_pid);
        else if (!strncmp(line, "VmRSS:", 6))
            sscanf(line, "VmRSS:\t%" SCNu64, &report->rss_kb);
    }

    fclose(status_handle);
    return OK;
}

static void read_cmdline_argc(pid_t pid, check_report_t *report) {
    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

    FILE *cmdline_handle = fopen(cmdline_path, "r");
    if (cmdline_handle == NULL)
        return; // argc stays 0, which reads as a kernel thread

    // arguments are NUL separated, so counting terminators counts arguments
    int argument_count = 0;
    int character;
    bool pending = false;

    while ((character = fgetc(cmdline_handle)) != EOF) {
        if (character == '\0') {
            if (pending)
                argument_count++;
            pending = false;
        } else {
            pending = true;
        }
    }
    if (pending)
        argument_count++;

    fclose(cmdline_handle);
    report->argc = argument_count;
}

// the restore execs this exact path with no arguments, see restorer.c
static void probe_exe(pid_t pid, check_report_t *report) {
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);

    ssize_t len = readlink(exe_link, report->exe_path, PATH_MAX - 1);
    if (len < 0) {
        if (errno == EACCES || errno == EPERM)
            add_reason(report, "not_inspectable",
                       "/proc/%d/exe cannot be read, run the engine as root",
                       pid);
        else
            add_reason(report, "exe_unreadable",
                       "the executable path cannot be resolved: %s",
                       strerror(errno));
        return;
    }

    report->exe_path[len] = '\0';

    // the dumper refuses an empty path, see read_exe_path in dumper.c
    if (len <= MIN_LEN_PATH) {
        add_reason(report, "exe_unreadable", "the executable path is empty");
        return;
    }

    size_t suffix_len = sizeof(DELETED_SUFFIX) - 1;
    if ((size_t)len > suffix_len &&
        !strcmp(report->exe_path + len - suffix_len, DELETED_SUFFIX)) {
        report->exe_path[len - suffix_len] = '\0';
        add_reason(report, "exe_deleted",
                   "the executable no longer exists, the restore could not "
                   "exec it");
        return;
    }

    if (access(report->exe_path, X_OK) != 0)
        add_reason(report, "exe_not_executable",
                   "the executable cannot be run by the engine: %s",
                   strerror(errno));
}

// the same walk the dumper does, through the same classify_maps_line, counting
// instead of copying
static void scan_maps(pid_t pid, check_report_t *report) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_handle = fopen(maps_path, "r");
    if (maps_handle == NULL) {
        if (errno == EACCES || errno == EPERM)
            add_reason(report, "not_inspectable",
                       "/proc/%d/maps cannot be read, run the engine as root",
                       pid);
        else
            add_reason(report, "gone",
                       "the process disappeared while it was inspected");
        return;
    }

    char maps_line[MAPS_LINE_MAX];
    maps_line_t parsed;
    char first_shared[PATH_MAX] = "";
    char first_device[PATH_MAX] = "";

    while (fgets(maps_line, sizeof(maps_line), maps_handle) != NULL) {
        if (!parse_maps_line(maps_line, &parsed))
            continue;

        vma_class_t vma_class = classify_maps_line(&parsed);

        if (vma_class == VMA_KERNEL) {
            report->kernel_maps++;
            continue;
        }

        if (vma_class == VMA_SKIP_SHARED) {
            report->shared_vmas++;
            if (first_shared[0] == '\0')
                snprintf(first_shared, sizeof(first_shared), "%s",
                         parsed.path[0] != '\0' ? parsed.path
                                                : "an anonymous mapping");
            continue;
        }

        if (vma_class != VMA_DUMP)
            continue;

        // a mapping of a device cannot be read back through /proc/<pid>/mem,
        // and a failed read aborts the whole dump
        if (!strncmp(parsed.path, "/dev/", 5)) {
            report->device_vmas++;
            if (first_device[0] == '\0')
                snprintf(first_device, sizeof(first_device), "%s", parsed.path);
        }

        report->dumpable_vmas++;
        report->snapshot_bytes += parsed.end - parsed.start;
    }

    if (ferror(maps_handle))
        add_reason(report, "gone", "reading the mappings failed halfway");

    fclose(maps_handle);

    if (report->shared_vmas > 0)
        add_reason(report, "shared_mapping",
                   "%u shared %s would be dropped silently, first %s",
                   report->shared_vmas,
                   report->shared_vmas == 1 ? "mapping" : "mappings",
                   first_shared);

    if (report->device_vmas > 0)
        add_reason(report, "device_mapping",
                   "%s cannot be read through /proc/%d/mem", first_device, pid);

    if (report->kernel_maps > KSNAP_MAX_KERNEL_MAPS)
        add_reason(report, "too_many_kernel_maps",
                   "the snapshot format holds %d kernel mappings, found %u",
                   KSNAP_MAX_KERNEL_MAPS, report->kernel_maps);

    if (report->dumpable_vmas == 0)
        add_reason(report, "no_dumpable_mapping",
                   "no mapping the engine would copy");
}

// descriptors are not part of the snapshot at all, so they are reported as
// facts and the panel decides how much that matters
static void scan_fds(pid_t pid, check_report_t *report) {
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);

    DIR *fd_handle = opendir(fd_path);
    if (fd_handle == NULL)
        return; // not readable is not a verdict, the counts stay at zero

    struct dirent *entry;
    while ((entry = readdir(fd_handle)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0]))
            continue;

        // the restored process inherits the stdio of the engine, which is what
        // the restore test relies on, so 0, 1 and 2 are not a loss
        if (!strcmp(entry->d_name, "0") || !strcmp(entry->d_name, "1") ||
            !strcmp(entry->d_name, "2"))
            continue;

        report->open_fds++;

        // read through the open directory, a descriptor name plus the path
        // would not fit a fixed buffer in the general case
        char target[PATH_MAX];
        ssize_t len = readlinkat(dirfd(fd_handle), entry->d_name, target,
                                 sizeof(target) - 1);
        if (len < 0)
            continue;
        target[len] = '\0';

        if (!strncmp(target, FD_SOCKET, sizeof(FD_SOCKET) - 1) ||
            !strncmp(target, FD_PIPE, sizeof(FD_PIPE) - 1) ||
            !strncmp(target, FD_ANON, sizeof(FD_ANON) - 1))
            report->volatile_fds++;
    }

    closedir(fd_handle);
}

static void count_children(pid_t pid, check_report_t *report) {
    char children_path[80];
    snprintf(children_path, sizeof(children_path), "/proc/%d/task/%d/children",
             pid, pid);

    FILE *children_handle = fopen(children_path, "r");
    if (children_handle == NULL)
        return;

    int child;
    while (fscanf(children_handle, "%d", &child) == 1)
        report->children++;

    fclose(children_handle);
}

// the first four steps of a dump, undone right away. PTRACE_SEIZE on its own
// does not stop the target, and the stop from PTRACE_INTERRUPT lasts until the
// detach below, so this is the cheapest honest answer to "would a dump attach".
static void probe_ptrace(pid_t pid, check_report_t *report) {
    int status;

    report->ptrace_probed = true;

    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1) {
        add_reason(report, "ptrace_refused", "cannot seize the process: %s",
                   strerror(errno));
        return;
    }

    if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == -1) {
        add_reason(report, "ptrace_refused", "cannot interrupt the process: %s",
                   strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    if (waitpid(pid, &status, 0) == -1 || !WIFSTOPPED(status))
        add_reason(report, "ptrace_refused",
                   "the process did not stop for the engine");
    else
        report->ptrace_ok = true;

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        add_reason(report, "ptrace_refused", "cannot detach again: %s",
                   strerror(errno));
        report->ptrace_ok = false;
    }
}

// one JSON object per line, so the output can be read as a stream and a single
// unparsable line never costs the whole sweep
static void print_report(const check_report_t *report) {
    printf("{\"pid\":%d,\"dumpable\":%s,\"reasons\":[", report->pid,
           report->reason_count == 0 ? "true" : "false");

    for (uint32_t i = 0; i < report->reason_count; i++) {
        printf("%s{\"code\":\"%s\",\"detail\":", i == 0 ? "" : ",",
               report->reasons[i].code);
        print_json_string(report->reasons[i].detail);
        printf("}");
    }

    printf("],\"facts\":{\"comm\":");
    print_json_string(report->comm);
    printf(",\"state\":\"%c\"", report->state);
    printf(",\"threads\":%d", report->threads);
    printf(",\"tracer_pid\":%d", report->tracer_pid);
    printf(",\"uid\":%u", report->uid);
    printf(",\"rss_kb\":%" PRIu64, report->rss_kb);
    printf(",\"argc\":%d", report->argc);
    printf(",\"exe\":");
    print_json_string(report->exe_path);
    printf(",\"open_fds\":%d", report->open_fds);
    printf(",\"volatile_fds\":%d", report->volatile_fds);
    printf(",\"children\":%d", report->children);
    printf(",\"dumpable_vmas\":%u", report->dumpable_vmas);
    printf(",\"kernel_maps\":%u", report->kernel_maps);
    printf(",\"shared_vmas\":%u", report->shared_vmas);
    printf(",\"device_vmas\":%u", report->device_vmas);
    printf(",\"snapshot_bytes\":%" PRIu64, report->snapshot_bytes);
    printf(",\"ptrace_probed\":%s", report->ptrace_probed ? "true" : "false");
    printf(",\"ptrace_ok\":%s", report->ptrace_ok ? "true" : "false");
    printf("}}\n");
}

// comm and the executable path are the only free form strings here, and a path
// may legally hold a quote or a backslash
static void print_json_string(const char *value) {
    putchar('"');

    for (const unsigned char *cursor = (const unsigned char *)value;
         *cursor != '\0'; cursor++) {
        switch (*cursor) {
        case '"':
            printf("\\\"");
            break;
        case '\\':
            printf("\\\\");
            break;
        case '\n':
            printf("\\n");
            break;
        case '\r':
            printf("\\r");
            break;
        case '\t':
            printf("\\t");
            break;
        default:
            if (*cursor < 0x20)
                printf("\\u%04x", *cursor);
            else
                putchar(*cursor);
        }
    }

    putchar('"');
}
