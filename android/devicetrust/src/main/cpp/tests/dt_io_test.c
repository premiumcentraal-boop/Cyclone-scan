#include "dt_io.h"
#include <assert.h>
#include <string.h>
int main(void) {
    char buf[16384]; size_t n = 0;
    assert(dt_read("/proc/self/status", buf, sizeof(buf), &n) == 0);
    assert(n && strstr(buf, "TracerPid:"));
    assert(dt_exists("/proc/self/status") == 1);
    assert(dt_exists("/proc/self/cyclone-nonexistent-entry") == 0);
    assert(dt_read("/proc/self/status", buf, 2, &n) == -1); /* truncated is unavailable */
    assert(dt_read("/proc/self/cyclone-nonexistent-entry", buf, sizeof(buf), &n) == -1);
    return 0;
}
