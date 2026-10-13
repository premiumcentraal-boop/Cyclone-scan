#define _GNU_SOURCE 1
#include "dt_io.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

/* Direct kernel entry: no libc open/read/access/syscall wrappers. No writes or sockets. */
static long raw3(long nr, long a, long b, long c) {
#if defined(__aarch64__)
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc");
    return x0;
#elif defined(__arm__)
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long ip __asm__("r12") = nr;
    __asm__ volatile("push {r7}\n\tmov r7, r12\n\tsvc 0\n\tpop {r7}"
        : "+r"(r0) : "r"(r1), "r"(r2), "r"(ip) : "memory", "cc");
    return r0;
#elif defined(__x86_64__)
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(nr), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory", "cc");
    return result;
#else
#error Unsupported native ABI
#endif
}
int dt_exists(const char *path) {
    long r = raw3(__NR_faccessat, AT_FDCWD, (long)path, F_OK);
    if (r == 0) return 1;
    return r == -ENOENT || r == -ENOTDIR ? 0 : -1;
}
int dt_read(const char *path, char *buf, size_t cap, size_t *size) {
    if (cap < 2) return -1;
    long fd;
    do { fd = raw3(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC); } while (fd == -EINTR);
    if (fd < 0) return -1;
    size_t used = 0;
    int ok = 1;
    for (;;) {
        char extra;
        char *dest = used < cap - 1 ? buf + used : &extra;
        size_t room = used < cap - 1 ? cap - 1 - used : 1;
        long n = raw3(__NR_read, fd, (long)dest, (long)room);
        if (n == -EINTR) continue;
        if (n < 0) { ok = 0; break; }
        if (n == 0) break;
        if (used == cap - 1) { ok = 0; break; }
        used += (size_t)n;
    }
    (void)raw3(__NR_close, fd, 0, 0);
    buf[used] = '\0';
    *size = used;
    /* Embedded NUL must not hide a trailing indicator. */
    for (size_t i = 0; i < used; ++i) if (!buf[i]) ok = 0;
    return ok ? 0 : -1;
}
