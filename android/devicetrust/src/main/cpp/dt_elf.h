#ifndef DT_ELF_H
#define DT_ELF_H
#include <stdint.h>
#include "dt_checks.h"
#define DT_MAX_SEGMENTS 8
struct dt_segment { uintptr_t address; size_t size; unsigned char digest[32]; };
struct dt_elf_baseline {
    struct dt_segment segments[DT_MAX_SEGMENTS];
    size_t count;
    uintptr_t marker;
    int ready;
};
int dt_range_readable(const char *maps, uintptr_t start, size_t size);
int dt_elf_capture(struct dt_elf_baseline *, const void *owned_marker);
enum dt_state dt_elf_check(const struct dt_elf_baseline *);
#endif
