#include "dt_checks.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static const char *maps = "", *mounts = "", *status = "TracerPid:\t0\n", *selinux = "1\n";
static const char *artifact;
static int unavailable;
static int fake_read(const char *path, char *buf, size_t cap, size_t *len) {
    if (unavailable) return -1;
    const char *s = "";
    if (strcmp(path, "/proc/self/maps") == 0) s = maps;
    if (strcmp(path, "/proc/self/mounts") == 0) s = mounts;
    if (strcmp(path, "/proc/self/status") == 0) s = status;
    if (strcmp(path, "/sys/fs/selinux/enforce") == 0) s = selinux;
    *len = strlen(s);
    if (*len >= cap) return -1;
    memcpy(buf, s, *len + 1); return 0;
}
static int fake_exists(const char *path) {
    if (unavailable) return -1;
    return artifact && strcmp(path, artifact) == 0;
}
int main(void) {
    struct dt_probe p = {fake_read, fake_exists};
    struct dt_result r;
    dt_collect(&p, &r);
    for (int i = 0; i < DT_CODE; ++i) assert(r.states[i] == DT_NOT_DETECTED);
    artifact = "/system/bin/su"; dt_collect(&p, &r); assert(r.states[DT_SU] == DT_DETECTED);
    artifact = "/data/adb/ksu"; dt_collect(&p, &r); assert(r.states[DT_ROOT_FRAMEWORK] == DT_DETECTED);
    artifact = "/data/adb/ap"; dt_collect(&p, &r); assert(r.states[DT_ROOT_FRAMEWORK] == DT_DETECTED);
    artifact = NULL;
    mounts = "none /system ext4 ro,rw,relatime 0 0\n";
    dt_collect(&p, &r); assert(r.states[DT_SYSTEM_RW] == DT_DETECTED);
    mounts = "magisk /data tmpfs ro 0 0\n";
    dt_collect(&p, &r); assert(r.states[DT_ROOT_FRAMEWORK] == DT_DETECTED);
    mounts = "none /system_ext ext4 rw 0 0\nnone /system ext4 ro,rwx 0 0\n";
    dt_collect(&p, &r); assert(r.states[DT_SYSTEM_RW] == DT_NOT_DETECTED);
    maps = "/host/libFRIDA.so\n/host/liblspd.so\n/host/zygisk.so\n";
    dt_collect(&p, &r);
    assert(r.states[DT_FRIDA] == DT_DETECTED);
    assert(r.states[DT_XPOSED] == DT_DETECTED);
    assert(r.states[DT_ZYGISK] == DT_DETECTED);
    maps = "";
    status = "Name: host\nTracerPid: 123\n";
    dt_collect(&p, &r); assert(r.states[DT_TRACER] == DT_DETECTED);
    assert(dt_tracer("TracerPid: -1\n") == DT_UNAVAILABLE);
    assert(dt_tracer("TracerPid: 999999999999999999999\n") == DT_UNAVAILABLE);
    assert(dt_tracer("TracerPid: 1junk\n") == DT_UNAVAILABLE);
    assert(dt_tracer("Name: host\n") == DT_UNAVAILABLE);
    selinux = "0\n"; dt_collect(&p, &r); assert(r.states[DT_SELINUX] == DT_DETECTED);
    selinux = "garbage"; dt_collect(&p, &r); assert(r.states[DT_SELINUX] == DT_UNAVAILABLE);
    unsigned char a[16] = {0}, b[16] = {0};
    assert(!dt_code_changed(a, b, sizeof(a)));
    b[7] = 1; assert(dt_code_changed(a, b, sizeof(a)));
    unavailable = 1; dt_collect(&p, &r);
    for (int i = 0; i < DT_COUNT; ++i) assert(r.states[i] == DT_UNAVAILABLE);
    dt_collect(NULL, &r); assert(r.states[DT_SU] == DT_UNAVAILABLE);
    puts("native parser and detector tests passed");
    return 0;
}
