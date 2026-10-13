#include "dt_checks.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

const char *const dt_names[DT_COUNT] = {"root_su", "root_magisk", "root_system_rw",
    "hook_frida", "hook_xposed", "hook_zygisk", "debug_traced",
    "selinux_permissive", "code_modified"};
const char *dt_state_name(enum dt_state s) {
    switch (s) {
        case DT_DETECTED: return "DETECTED";
        case DT_NOT_DETECTED: return "NOT_DETECTED";
        case DT_UNSUPPORTED: return "UNSUPPORTED";
        default: return "UNAVAILABLE";
    }
}
static int contains_lower(const char *text, const char *token) {
    size_t n = strlen(token);
    for (; *text; ++text) {
        size_t i = 0;
        while (i < n && text[i] &&
            (unsigned char)tolower((unsigned char)text[i]) == (unsigned char)token[i]) ++i;
        if (i == n) return 1;
    }
    return 0;
}
static enum dt_state artifacts(const struct dt_probe *p, const char *const *paths, size_t n) {
    int denied = 0;
    for (size_t i = 0; i < n; ++i) {
        int r = p->exists(paths[i]);
        if (r > 0) return DT_DETECTED;
        if (r < 0) denied = 1;
    }
    return denied ? DT_UNAVAILABLE : DT_NOT_DETECTED;
}
enum dt_state dt_tracer(const char *text) {
    const char *line = text;
    while (*line) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            const char *v = line + 10;
            while (*v == ' ' || *v == '\t') ++v;
            if (!isdigit((unsigned char)*v)) return DT_UNAVAILABLE;
            unsigned long pid = 0;
            while (isdigit((unsigned char)*v)) {
                unsigned digit = (unsigned)(*v++ - '0');
                if (pid > ((unsigned long)INT_MAX - digit) / 10) return DT_UNAVAILABLE;
                pid = pid * 10 + digit;
            }
            while (*v == ' ' || *v == '\t' || *v == '\r') ++v;
            if (*v && *v != '\n') return DT_UNAVAILABLE;
            return pid ? DT_DETECTED : DT_NOT_DETECTED;
        }
        const char *next = strchr(line, '\n');
        if (!next) break;
        line = next + 1;
    }
    return DT_UNAVAILABLE;
}
static int system_rw(const char *text) {
    while (*text) {
        const char *end = strchr(text, '\n');
        if (!end) end = text + strlen(text);
        const char *p = text;
        const char *fields[4]; size_t lengths[4];
        int count = 0;
        while (p < end && count < 4) {
            while (p < end && (*p == ' ' || *p == '\t')) ++p;
            fields[count] = p;
            while (p < end && *p != ' ' && *p != '\t') ++p;
            lengths[count] = (size_t)(p - fields[count]);
            ++count;
        }
        if (count == 4 && lengths[1] == 7 && memcmp(fields[1], "/system", 7) == 0) {
            const char *opt = fields[3], *limit = opt + lengths[3];
            while (opt < limit) {
                const char *finish = opt;
                while (finish < limit && *finish != ',') ++finish;
                if (finish - opt == 2 && memcmp(opt, "rw", 2) == 0) return 1;
                opt = finish < limit ? finish + 1 : limit;
            }
        }
        text = *end ? end + 1 : end;
    }
    return 0;
}
int dt_code_changed(const unsigned char *a, const unsigned char *b, size_t n) {
#if defined(DT_MUTATE_CHECK) && DT_MUTATE_CHECK == 8
    (void)a; (void)b; (void)n; return 0;
#else
    return memcmp(a, b, n) != 0;
#endif
}
void dt_collect(const struct dt_probe *p, struct dt_result *out) {
    static const char *const su[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su", "/vendor/bin/su",
        "/su/bin/su", "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/system/bin/failsafe/su", "/odm/bin/su"};
    static const char *const root[] = {
        "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules", "/cache/.disable_magisk",
        "/dev/.magisk.unblock", "/debug_ramdisk/.magisk", "/data/adb/ksu", "/data/adb/ap"};
    for (int i = 0; i < DT_COUNT; ++i) out->states[i] = DT_UNAVAILABLE;
    if (!p || !p->read || !p->exists) return;
    out->states[DT_SU] = artifacts(p, su, sizeof(su) / sizeof(su[0]));
    out->states[DT_ROOT_FRAMEWORK] = artifacts(p, root, sizeof(root) / sizeof(root[0]));
    const size_t cap = 512 * 1024 + 1;
    char *buf = malloc(cap);
    if (!buf) return;
    size_t len = 0;
    if (p->read("/proc/self/mounts", buf, cap, &len) == 0) {
        if (contains_lower(buf, "magisk")) out->states[DT_ROOT_FRAMEWORK] = DT_DETECTED;
        out->states[DT_SYSTEM_RW] = system_rw(buf) ? DT_DETECTED : DT_NOT_DETECTED;
    } else if (out->states[DT_ROOT_FRAMEWORK] != DT_DETECTED) {
        out->states[DT_ROOT_FRAMEWORK] = DT_UNAVAILABLE;
    }
    if (p->read("/proc/self/maps", buf, cap, &len) == 0) {
        out->states[DT_FRIDA] = (contains_lower(buf, "frida") ||
            contains_lower(buf, "gum-js-loop") || contains_lower(buf, "gadget")) ? DT_DETECTED : DT_NOT_DETECTED;
        static const char *const tokens[] = {"xposedbridge", "liblspd", "lspd", "edxp", "libriru", "libsandhook"};
        int xposed = 0;
        for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); ++i) xposed |= contains_lower(buf, tokens[i]);
        out->states[DT_XPOSED] = xposed ? DT_DETECTED : DT_NOT_DETECTED;
        out->states[DT_ZYGISK] = contains_lower(buf, "zygisk") ? DT_DETECTED : DT_NOT_DETECTED;
    }
    if (p->read("/proc/self/status", buf, cap, &len) == 0) out->states[DT_TRACER] = dt_tracer(buf);
    if (p->read("/sys/fs/selinux/enforce", buf, cap, &len) == 0) {
        if (strcmp(buf, "0") == 0 || strcmp(buf, "0\n") == 0) out->states[DT_SELINUX] = DT_DETECTED;
        else if (strcmp(buf, "1") == 0 || strcmp(buf, "1\n") == 0) out->states[DT_SELINUX] = DT_NOT_DETECTED;
    }
    free(buf);
#if defined(DT_MUTATE_CHECK) && DT_MUTATE_CHECK < 8
    out->states[DT_MUTATE_CHECK] = DT_NOT_DETECTED;
#endif
}
