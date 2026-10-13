#include "dt_checks.h"
#include "dt_io.h"
#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>

/* Only known, owned compiled functions are read, never caller-supplied addresses.
 * These functions exceed 16 bytes on the supported ABIs (verified by CI symbol-size checks).
 * On-load evidence detects later modification; it cannot attest a clean initial load. */
#define BASELINE_BYTES 16
static unsigned char baseline[3][BASELINE_BYTES];
static const void *const owned[] = {(const void *)dt_collect, (const void *)dt_read, (const void *)dt_tracer};
static const unsigned char *code_address(size_t i) {
    uintptr_t address = (uintptr_t)owned[i];
#if defined(__arm__)
    address &= ~(uintptr_t)1;
#endif
    return (const unsigned char *)address;
}
static int baseline_ready;
static pthread_mutex_t scan_lock = PTHREAD_MUTEX_INITIALIZER;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    for (size_t i = 0; i < 3; ++i) memcpy(baseline[i], code_address(i), BASELINE_BYTES);
    baseline_ready = 1;
    return JNI_VERSION_1_6;
}
JNIEXPORT jstring JNICALL Java_com_devicetrust_client_signals_JniNativeProbe_scanRaw(JNIEnv *env, jobject self) {
    (void)self;
    if (pthread_mutex_lock(&scan_lock) != 0) return NULL;
    struct dt_probe probe = {dt_read, dt_exists};
    struct dt_result result;
    dt_collect(&probe, &result);
    if (baseline_ready) {
        int changed = 0;
        for (size_t i = 0; i < 3; ++i)
            changed |= dt_code_changed(baseline[i], code_address(i), BASELINE_BYTES);
        result.states[DT_CODE] = changed ? DT_DETECTED : DT_NOT_DETECTED;
    }
    char json[2048]; size_t used = 0;
    int n = snprintf(json, sizeof(json), "{");
    if (n < 0) { pthread_mutex_unlock(&scan_lock); return NULL; }
    used = (size_t)n;
    for (int i = 0; i < DT_COUNT; ++i) {
        n = snprintf(json + used, sizeof(json) - used,
            "%s\"native_%s\":%s,\"native_%s_status\":\"%s\"", i ? "," : "",
            dt_names[i], result.states[i] == DT_DETECTED ? "true" : "false",
            dt_names[i], dt_state_name(result.states[i]));
        if (n < 0 || (size_t)n + 2 > sizeof(json) - used) {
            pthread_mutex_unlock(&scan_lock); return NULL;
        }
        used += (size_t)n;
    }
    json[used++] = '}'; json[used] = '\0';
    pthread_mutex_unlock(&scan_lock);
    return (*env)->NewStringUTF(env, json);
}
