#ifndef DT_CHECKS_H
#define DT_CHECKS_H
#include <stddef.h>
enum dt_state { DT_NOT_DETECTED, DT_DETECTED, DT_UNAVAILABLE, DT_UNSUPPORTED };
enum dt_check { DT_SU, DT_ROOT_FRAMEWORK, DT_SYSTEM_RW, DT_FRIDA, DT_XPOSED,
    DT_ZYGISK, DT_TRACER, DT_SELINUX, DT_CODE, DT_COUNT };
struct dt_result { enum dt_state states[DT_COUNT]; };
struct dt_probe {
    /* read returns 0 only for a complete, NUL-terminated read; errors are unavailable. */
    int (*read)(const char *, char *, size_t, size_t *);
    /* 1 present, 0 absent, -1 unavailable. */
    int (*exists)(const char *);
};
extern const char *const dt_names[DT_COUNT];
void dt_collect(const struct dt_probe *, struct dt_result *);
enum dt_state dt_tracer(const char *);
int dt_code_changed(const unsigned char *, const unsigned char *, size_t);
const char *dt_state_name(enum dt_state);
#endif
