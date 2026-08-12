#ifndef DUMP_FORMAT_H
#define DUMP_FORMAT_H

#include <linux/limits.h>
#include <stdint.h>
#include <sys/user.h>

// On disk layout of one snapshot:
//
//   [ksnap_dump_header_t]                       at offset 0
//   [vma_descriptor_t] x vma_count              at vma_table_offset
//   [path string pool]                          at path_pool_offset
//   [segment payloads]                          first one at data_offset
//

#define KSNAP_MAGIC "KSNAPDMP"
#define KSNAP_MAGIC_LEN 8
#define KSNAP_FORMAT_VERSION 2

// room for [vvar] [vvar_vclock] and [vdso]
#define KSNAP_MAX_KERNEL_MAPS 4
#define KSNAP_KERNEL_MAP_NAME_LEN 32

// kernel owned mapping
// the content is useless to copy but the address has to be kept
typedef struct {
    uint64_t start_address;
    uint64_t size;
    char name[KSNAP_KERNEL_MAP_NAME_LEN]; // "[vdso]", "[vvar]", ...
} kernel_map_t;

typedef struct {
    char magic[KSNAP_MAGIC_LEN]; // KSNAP_MAGIC, not NUL terminated
    uint32_t version;
    uint32_t vma_count;
    uint64_t vma_table_offset;
    uint64_t path_pool_offset;
    uint64_t path_pool_size;
    uint64_t data_offset;
    uint32_t exe_path_len;
    char exe_path[PATH_MAX];
    uint32_t kernel_map_count;
    kernel_map_t kernel_maps[KSNAP_MAX_KERNEL_MAPS];
    struct user_regs_struct regs;
} ksnap_dump_header_t;

typedef struct {
    uint64_t start_address;
    uint64_t size;
    uint64_t file_offset; // offset inside the backing file, 0 when anonymous
    uint64_t data_offset; // where the payload of this vma starts in the dump
    uint32_t prot;        // PROT_READ | PROT_WRITE | PROT_EXEC
    uint32_t map_flags;   // MAP_PRIVATE or MAP_SHARED
    uint32_t path_offset; // byte offset into the path pool
    uint32_t path_len;    // length without the terminator, 0 when anonymous
} vma_descriptor_t;

_Static_assert(sizeof(vma_descriptor_t) == 48,
               "vma_descriptor_t must stay packed, bump KSNAP_FORMAT_VERSION "
               "when it changes");

#endif // DUMP_FORMAT_H
