#include "dt_checks.h"
#include "dt_elf.h"
#include "dt_io.h"
#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>

/* All readable executable segments of this library are measured after relocation.
 * Owned module only. Initial cleanliness is not established by this baseline. */
static struct dt_elf_baseline executable_baseline;
static pthread_mutex_t scan_lock = PTHREAD_MUTEX_INITIALIZER;
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    (void)dt_elf_capture(&executable_baseline, (const void *)dt_collect);
    return JNI_VERSION_1_6;
}
JNIEXPORT jstring JNICALL Java_com_devicetrust_client_signals_JniNativeProbe_scanRaw(JNIEnv *env, jobject self) {
    (void)self;
    if (pthread_mutex_lock(&scan_lock) != 0) return NULL;
    struct dt_probe probe = {dt_read, dt_exists};
    struct dt_result result;
    dt_collect(&probe, &result);
    result.states[DT_CODE] = dt_elf_check(&executable_baseline);
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
