#include <jni.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libhogman.h"

#define HOGMAN_STATE_KEY_LEN 32

static JavaVM *g_jvm = NULL;

typedef struct {
    jobject target;
    jmethodID protect_mid;
    jmethodID reconfig_mid;
    int active;
} hogman_cb_state_t;

static pthread_mutex_t g_cb_mu = PTHREAD_MUTEX_INITIALIZER;
static hogman_cb_state_t g_cb = { NULL, NULL, NULL, 0 };

static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static jstring take_go_json(JNIEnv *env, char *raw) {
    if (raw == NULL) {
        return (*env)->NewStringUTF(env, "{\"ok\":false,\"error\":\"null native response\"}");
    }
    jstring out = (*env)->NewStringUTF(env, raw);
    hogman_free(raw);
    return out;
}

static int copy_state_key(JNIEnv *env, jbyteArray arr, uint8_t out[HOGMAN_STATE_KEY_LEN]) {
    if (arr == NULL) {
        return 0;
    }
    jsize n = (*env)->GetArrayLength(env, arr);
    if (n != HOGMAN_STATE_KEY_LEN) {
        return 0;
    }
    (*env)->GetByteArrayRegion(env, arr, 0, HOGMAN_STATE_KEY_LEN, (jbyte *)out);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        secure_zero(out, HOGMAN_STATE_KEY_LEN);
        return 0;
    }
    return 1;
}

static const char *get_utf_or_empty(JNIEnv *env, jstring s, int *needs_release) {
    if (s == NULL) {
        *needs_release = 0;
        return "";
    }
    const char *c = (*env)->GetStringUTFChars(env, s, NULL);
    if (c == NULL) {
        *needs_release = 0;
        return "";
    }
    *needs_release = 1;
    return c;
}

static void release_utf(JNIEnv *env, jstring s, const char *c, int needs_release) {
    if (needs_release && s != NULL && c != NULL) {
        (*env)->ReleaseStringUTFChars(env, s, c);
    }
}

static JNIEnv *attach_thread(int *did_attach) {
    *did_attach = 0;
    if (g_jvm == NULL) {
        return NULL;
    }
    JNIEnv *env = NULL;
    jint rc = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (rc == JNI_OK) {
        return env;
    }
    if (rc == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) == JNI_OK) {
            *did_attach = 1;
            return env;
        }
    }
    return NULL;
}

static void detach_if_needed(int did_attach) {
    if (did_attach && g_jvm != NULL) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
}

static void clear_callback_state_locked(JNIEnv *env) {
    g_cb.active = 0;
    if (g_cb.target != NULL && env != NULL) {
        (*env)->DeleteGlobalRef(env, g_cb.target);
    }
    g_cb.target = NULL;
    g_cb.protect_mid = NULL;
    g_cb.reconfig_mid = NULL;
}

static int jni_protect_cb(int fd, void *user_data) {
    (void)user_data;
    int did_attach = 0;
    JNIEnv *env = attach_thread(&did_attach);
    if (env == NULL) {
        return -1;
    }

    jobject local_target = NULL;
    jmethodID mid = NULL;
    pthread_mutex_lock(&g_cb_mu);
    if (g_cb.active && g_cb.target != NULL && g_cb.protect_mid != NULL) {
        local_target = (*env)->NewLocalRef(env, g_cb.target);
        mid = g_cb.protect_mid;
    }
    pthread_mutex_unlock(&g_cb_mu);

    int rc = -1;
    if (local_target != NULL && mid != NULL) {
        rc = (int)(*env)->CallIntMethod(env, local_target, mid, (jint)fd);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            rc = -1;
        }
        (*env)->DeleteLocalRef(env, local_target);
    }

    detach_if_needed(did_attach);
    return rc;
}

static int jni_reconfig_cb(const char *reconfig_json, void *user_data) {
    (void)user_data;
    int did_attach = 0;
    JNIEnv *env = attach_thread(&did_attach);
    if (env == NULL) {
        return -2;
    }

    jobject local_target = NULL;
    jmethodID mid = NULL;
    pthread_mutex_lock(&g_cb_mu);
    if (g_cb.active && g_cb.target != NULL && g_cb.reconfig_mid != NULL) {
        local_target = (*env)->NewLocalRef(env, g_cb.target);
        mid = g_cb.reconfig_mid;
    }
    pthread_mutex_unlock(&g_cb_mu);

    int rc = -2;
    if (local_target != NULL && mid != NULL) {
        jstring jjson = (*env)->NewStringUTF(env, reconfig_json != NULL ? reconfig_json : "{}");
        if (jjson != NULL) {
            rc = (int)(*env)->CallIntMethod(env, local_target, mid, jjson);
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
                rc = -2;
            }
            (*env)->DeleteLocalRef(env, jjson);
        }
        (*env)->DeleteLocalRef(env, local_target);
    }

    detach_if_needed(did_attach);
    return rc;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT jstring JNICALL
Java_network_hogman_mobile_core_HogmanNative_nativeParseLink(
    JNIEnv *env, jclass clazz, jstring rawLink) {
    (void)clazz;
    int rel_link = 0;
    const char *c_link = get_utf_or_empty(env, rawLink, &rel_link);
    char *res = hogman_parse_link((char *)c_link);
    release_utf(env, rawLink, c_link, rel_link);
    return take_go_json(env, res);
}

JNIEXPORT jstring JNICALL
Java_network_hogman_mobile_core_HogmanNative_nativeJoin(
    JNIEnv *env,
    jclass clazz,
    jstring dataDir,
    jbyteArray stateKey,
    jstring rawLink,
    jstring handle,
    jstring deviceName,
    jstring controlCAPEM) {
    (void)clazz;
    uint8_t key_buf[HOGMAN_STATE_KEY_LEN];
    if (!copy_state_key(env, stateKey, key_buf)) {
        return (*env)->NewStringUTF(
            env, "{\"ok\":false,\"error\":\"state_key must be exactly 32 bytes\"}");
    }

    int rel_dir = 0, rel_link = 0, rel_handle = 0, rel_dev = 0, rel_ca = 0;
    const char *c_dir = get_utf_or_empty(env, dataDir, &rel_dir);
    const char *c_link = get_utf_or_empty(env, rawLink, &rel_link);
    const char *c_handle = get_utf_or_empty(env, handle, &rel_handle);
    const char *c_dev = get_utf_or_empty(env, deviceName, &rel_dev);
    const char *c_ca = get_utf_or_empty(env, controlCAPEM, &rel_ca);

    char *res = hogman_join(
        (char *)c_dir,
        key_buf,
        HOGMAN_STATE_KEY_LEN,
        (char *)c_link,
        (char *)c_handle,
        (char *)c_dev,
        (char *)c_ca);

    secure_zero(key_buf, sizeof(key_buf));
    release_utf(env, dataDir, c_dir, rel_dir);
    release_utf(env, rawLink, c_link, rel_link);
    release_utf(env, handle, c_handle, rel_handle);
    release_utf(env, deviceName, c_dev, rel_dev);
    release_utf(env, controlCAPEM, c_ca, rel_ca);

    return take_go_json(env, res);
}

JNIEXPORT jstring JNICALL
Java_network_hogman_mobile_core_HogmanNative_nativeListPens(
    JNIEnv *env, jclass clazz, jstring dataDir) {
    (void)clazz;
    int rel_dir = 0;
    const char *c_dir = get_utf_or_empty(env, dataDir, &rel_dir);
    char *res = hogman_list_pens((char *)c_dir);
    release_utf(env, dataDir, c_dir, rel_dir);
    return take_go_json(env, res);
}

JNIEXPORT jstring JNICALL
Java_network_hogman_mobile_core_HogmanNative_nativeStartTunnel(
    JNIEnv *env,
    jclass clazz,
    jstring dataDir,
    jbyteArray stateKey,
    jstring zone,
    jint mtu,
    jstring upstreamDNSJSON,
    jobject callbackTarget) {
    (void)clazz;
    uint8_t key_buf[HOGMAN_STATE_KEY_LEN];
    if (!copy_state_key(env, stateKey, key_buf)) {
        return (*env)->NewStringUTF(
            env, "{\"ok\":false,\"error\":\"state_key must be exactly 32 bytes\"}");
    }

    if (callbackTarget == NULL) {
        secure_zero(key_buf, sizeof(key_buf));
        return (*env)->NewStringUTF(
            env, "{\"ok\":false,\"error\":\"tunnel callback target is required\"}");
    }

    jclass cb_cls = (*env)->GetObjectClass(env, callbackTarget);
    if (cb_cls == NULL) {
        secure_zero(key_buf, sizeof(key_buf));
        return (*env)->NewStringUTF(
            env, "{\"ok\":false,\"error\":\"could not resolve callback class\"}");
    }
    jmethodID protect_mid = (*env)->GetMethodID(env, cb_cls, "protectFd", "(I)I");
    jmethodID reconfig_mid =
        (*env)->GetMethodID(env, cb_cls, "onTunnelReconfig", "(Ljava/lang/String;)I");
    (*env)->DeleteLocalRef(env, cb_cls);
    if (protect_mid == NULL || reconfig_mid == NULL) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        secure_zero(key_buf, sizeof(key_buf));
        return (*env)->NewStringUTF(
            env, "{\"ok\":false,\"error\":\"callback target missing required methods\"}");
    }

    // Stop any previous tunnel first so old Go goroutines finish before swapping callback refs.
    char *stopped = hogman_stop_tunnel();
    if (stopped != NULL) {
        hogman_free(stopped);
    }

    jobject new_global = (*env)->NewGlobalRef(env, callbackTarget);
    if (new_global == NULL) {
        secure_zero(key_buf, sizeof(key_buf));
        return (*env)->NewStringUTF(
            env, "{\"ok\":false,\"error\":\"failed to allocate callback global ref\"}");
    }

    pthread_mutex_lock(&g_cb_mu);
    clear_callback_state_locked(env);
    g_cb.target = new_global;
    g_cb.protect_mid = protect_mid;
    g_cb.reconfig_mid = reconfig_mid;
    g_cb.active = 1;
    pthread_mutex_unlock(&g_cb_mu);

    int rel_dir = 0, rel_zone = 0, rel_dns = 0;
    const char *c_dir = get_utf_or_empty(env, dataDir, &rel_dir);
    const char *c_zone = get_utf_or_empty(env, zone, &rel_zone);
    const char *c_dns = get_utf_or_empty(env, upstreamDNSJSON, &rel_dns);

    char *res = hogman_start_tunnel(
        (char *)c_dir,
        key_buf,
        HOGMAN_STATE_KEY_LEN,
        (char *)c_zone,
        (int)mtu,
        (char *)c_dns,
        jni_protect_cb,
        jni_reconfig_cb,
        NULL);

    secure_zero(key_buf, sizeof(key_buf));
    release_utf(env, dataDir, c_dir, rel_dir);
    release_utf(env, zone, c_zone, rel_zone);
    release_utf(env, upstreamDNSJSON, c_dns, rel_dns);

    return take_go_json(env, res);
}

JNIEXPORT jstring JNICALL
Java_network_hogman_mobile_core_HogmanNative_nativeUpdateNetwork(
    JNIEnv *env, jclass clazz, jstring upstreamDNSJSON, jboolean linkChanged) {
    (void)clazz;
    int rel_dns = 0;
    const char *c_dns = get_utf_or_empty(env, upstreamDNSJSON, &rel_dns);
    char *res = hogman_update_network((char *)c_dns, linkChanged ? 1 : 0);
    release_utf(env, upstreamDNSJSON, c_dns, rel_dns);
    return take_go_json(env, res);
}

JNIEXPORT jstring JNICALL
Java_network_hogman_mobile_core_HogmanNative_nativeStatus(JNIEnv *env, jclass clazz) {
    (void)clazz;
    char *res = hogman_status();
    return take_go_json(env, res);
}

JNIEXPORT jstring JNICALL
Java_network_hogman_mobile_core_HogmanNative_nativeStopTunnel(JNIEnv *env, jclass clazz) {
    (void)clazz;
    // Mark callbacks inactive before stopping Go goroutines, then delete the GlobalRef
    // only after hogman_stop_tunnel() has joined watchTunnel and shut down wgengine.
    pthread_mutex_lock(&g_cb_mu);
    g_cb.active = 0;
    pthread_mutex_unlock(&g_cb_mu);

    char *res = hogman_stop_tunnel();

    pthread_mutex_lock(&g_cb_mu);
    clear_callback_state_locked(env);
    pthread_mutex_unlock(&g_cb_mu);

    return take_go_json(env, res);
}

JNIEXPORT jstring JNICALL
Java_network_hogman_mobile_core_HogmanNative_nativeLeave(
    JNIEnv *env,
    jclass clazz,
    jstring dataDir,
    jbyteArray stateKey,
    jstring zone,
    jboolean force) {
    (void)clazz;
    uint8_t key_buf[HOGMAN_STATE_KEY_LEN];
    if (!copy_state_key(env, stateKey, key_buf)) {
        return (*env)->NewStringUTF(
            env, "{\"ok\":false,\"error\":\"state_key must be exactly 32 bytes\"}");
    }

    int rel_dir = 0, rel_zone = 0;
    const char *c_dir = get_utf_or_empty(env, dataDir, &rel_dir);
    const char *c_zone = get_utf_or_empty(env, zone, &rel_zone);

    char *res = hogman_leave(
        (char *)c_dir,
        key_buf,
        HOGMAN_STATE_KEY_LEN,
        (char *)c_zone,
        force ? 1 : 0);

    secure_zero(key_buf, sizeof(key_buf));
    release_utf(env, dataDir, c_dir, rel_dir);
    release_utf(env, zone, c_zone, rel_zone);

    return take_go_json(env, res);
}
