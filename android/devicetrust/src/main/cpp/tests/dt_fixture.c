/* Dedicated host-only fixture. Never shipped in the APK. */
__attribute__((noinline,visibility("default"))) int dt_fixture(int value) {
    volatile int copy=value;
    return copy*3+7;
}
