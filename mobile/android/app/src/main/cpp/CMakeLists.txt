cmake_minimum_required(VERSION 3.22.1)
project("hogman_jni" C)

set(HOGMAN_CORE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../build/android")
set(HOGMAN_SO "${HOGMAN_CORE_ROOT}/jniLibs/${ANDROID_ABI}/libhogman.so")
set(HOGMAN_INC "${HOGMAN_CORE_ROOT}/include")

if(NOT EXISTS "${HOGMAN_SO}")
    message(FATAL_ERROR
        "Missing ${HOGMAN_SO}. Run mobile/build-core.sh android from the repository root first.")
endif()

add_library(hogman_core SHARED IMPORTED)
set_target_properties(hogman_core PROPERTIES
    IMPORTED_LOCATION "${HOGMAN_SO}"
    IMPORTED_SONAME "libhogman.so")

add_library(hogman_jni SHARED hogman_jni.c)
target_include_directories(hogman_jni PRIVATE "${HOGMAN_INC}")
target_link_options(hogman_jni PRIVATE "-Wl,-z,max-page-size=16384")
target_link_libraries(hogman_jni PRIVATE hogman_core)
