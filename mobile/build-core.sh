#!/usr/bin/env bash
# Build the shared Hogman Mobile Go core (core/join/mobile/cabi) for Android
# (libhogman.so + libhogman.h with 16 KB ELF alignment) and/or iOS
# (HogmanCore.xcframework).
#
# Usage:
#   mobile/build-core.sh android        # arm64-v8a + x86_64 .so under mobile/build/android
#   mobile/build-core.sh ios            # HogmanCore.xcframework under mobile/build/ios
#   mobile/build-core.sh all            # both
#
# Set HOGMAN_MOBILE_DEBUG=1 to include -tags hogman_mobile_debug (enables
# control_ca_pem for staging/test harnesses; omitted in release builds).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JOIN_DIR="$ROOT/core/join"
OUT_ROOT="${OUT_DIR:-$ROOT/mobile/build}"
TARGET="${1:-all}"

MOBILE_TAGS="ts_omit_netstack,ts_omit_peerapiserver,ts_omit_peerapiclient,ts_omit_ssh,ts_omit_taildrop,ts_omit_drive,ts_omit_serve,ts_omit_webclient,ts_omit_webbrowser,ts_omit_capture,ts_omit_bird,ts_omit_aws,ts_omit_cloud,ts_omit_kube,ts_omit_tpm,ts_omit_dbus,ts_omit_iptables,ts_omit_networkmanager,ts_omit_resolved,ts_omit_sdnotify,ts_omit_synology,ts_omit_systray,ts_omit_syspolicy,ts_omit_wakeonlan,ts_omit_advertiseexitnode,ts_omit_advertiseroutes,ts_omit_useexitnode,ts_omit_useroutes,ts_omit_appconnectors,ts_omit_relayserver,ts_omit_tailnetlock,ts_omit_c2n,ts_omit_clientupdate,ts_omit_clientmetrics,ts_omit_logtail,ts_omit_netlog,ts_omit_portlist,ts_omit_posture,ts_omit_ace,ts_omit_acme,ts_omit_completion,ts_omit_completion_scripts,ts_omit_doctor,ts_omit_tap,ts_omit_desktop_sessions,ts_omit_flashappliance,ts_omit_identityfederation,ts_omit_oauthkey,ts_omit_outboundproxy,ts_omit_useproxy,ts_omit_remoteconfig,ts_omit_cliconndiag,ts_omit_qrcodes,ts_omit_gro,ts_omit_debug,ts_omit_debugportmapper,ts_omit_debugeventbus"
if [ "${HOGMAN_MOBILE_DEBUG:-0}" = "1" ]; then
  MOBILE_TAGS="${MOBILE_TAGS},hogman_mobile_debug"
fi

find_ndk() {
  if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ]; then
    echo "$ANDROID_NDK_HOME"
    return
  fi
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
  if [ -d "$sdk/ndk" ]; then
    ls -1d "$sdk/ndk"/* 2>/dev/null | sort -V | tail -n 1
    return
  fi
  echo "error: ANDROID_NDK_HOME not set and no NDK found under $sdk/ndk" >&2
  exit 1
}

build_android() {
  local ndk host_tag tc out_dir api
  ndk="$(find_ndk)"
  case "$(uname -s)" in
    Darwin) host_tag="darwin-x86_64" ;;
    Linux)  host_tag="linux-x86_64" ;;
    *)      echo "unsupported host OS $(uname -s)" >&2; exit 1 ;;
  esac
  tc="$ndk/toolchains/llvm/prebuilt/$host_tag/bin"
  api="${ANDROID_API:-28}"
  out_dir="$OUT_ROOT/android"
  mkdir -p "$out_dir/jniLibs/arm64-v8a" "$out_dir/jniLibs/x86_64" "$out_dir/include"

  echo "==> Building Android arm64-v8a (API $api, 16 KB page-aligned)"
  (
    cd "$JOIN_DIR"
    CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
      CC="$tc/aarch64-linux-android${api}-clang" \
      CGO_LDFLAGS="-Wl,-soname,libhogman.so -Wl,-z,max-page-size=16384" \
      go build -trimpath -ldflags="-s -w" -tags "$MOBILE_TAGS" -buildmode=c-shared \
      -o "$out_dir/jniLibs/arm64-v8a/libhogman.so" ./mobile/cabi
  )
  mv "$out_dir/jniLibs/arm64-v8a/libhogman.h" "$out_dir/include/libhogman.h"

  echo "==> Building Android x86_64 (API $api, 16 KB page-aligned)"
  (
    cd "$JOIN_DIR"
    CGO_ENABLED=1 GOOS=android GOARCH=amd64 \
      CC="$tc/x86_64-linux-android${api}-clang" \
      CGO_LDFLAGS="-Wl,-soname,libhogman.so -Wl,-z,max-page-size=16384" \
      go build -trimpath -ldflags="-s -w" -tags "$MOBILE_TAGS" -buildmode=c-shared \
      -o "$out_dir/jniLibs/x86_64/libhogman.so" ./mobile/cabi
  )
  rm -f "$out_dir/jniLibs/x86_64/libhogman.h"

  ls -lh "$out_dir/jniLibs/arm64-v8a/libhogman.so" "$out_dir/jniLibs/x86_64/libhogman.so"
}

build_ios() {
  local out_dir ios_sdk sim_sdk ios_cc sim_cc min_ios
  out_dir="$OUT_ROOT/ios"
  min_ios="${IOS_MIN_VERSION:-16.0}"
  ios_sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
  sim_sdk="$(xcrun --sdk iphonesimulator --show-sdk-path)"
  ios_cc="$(xcrun --sdk iphoneos --find clang)"
  sim_cc="$(xcrun --sdk iphonesimulator --find clang)"

  rm -rf "$out_dir"
  mkdir -p "$out_dir/device/headers" "$out_dir/sim/headers"

  echo "==> Building iOS arm64 (iphoneos, min iOS $min_ios)"
  (
    cd "$JOIN_DIR"
    CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
      CC="$ios_cc" \
      CGO_CFLAGS="-isysroot $ios_sdk -miphoneos-version-min=$min_ios -arch arm64" \
      CGO_LDFLAGS="-isysroot $ios_sdk -miphoneos-version-min=$min_ios -arch arm64" \
      go build -trimpath -ldflags="-s -w" -tags "$MOBILE_TAGS" -buildmode=c-archive \
      -o "$out_dir/device/libhogman.a" ./mobile/cabi
  )
  mv "$out_dir/device/libhogman.h" "$out_dir/device/headers/libhogman.h"

  echo "==> Building iOS Simulator arm64 (iphonesimulator, min iOS $min_ios)"
  (
    cd "$JOIN_DIR"
    CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
      CC="$sim_cc" \
      CGO_CFLAGS="-isysroot $sim_sdk -mios-simulator-version-min=$min_ios -arch arm64" \
      CGO_LDFLAGS="-isysroot $sim_sdk -mios-simulator-version-min=$min_ios -arch arm64" \
      go build -trimpath -ldflags="-s -w" -tags "$MOBILE_TAGS" -buildmode=c-archive \
      -o "$out_dir/sim/libhogman.a" ./mobile/cabi
  )
  mv "$out_dir/sim/libhogman.h" "$out_dir/sim/headers/libhogman.h"

  for d in "$out_dir/device/headers" "$out_dir/sim/headers"; do
    cat >"$d/module.modulemap" <<'EOF'
module HogmanCore {
    header "libhogman.h"
    export *
}
EOF
  done

  echo "==> Packaging HogmanCore.xcframework"
  xcodebuild -create-xcframework \
    -library "$out_dir/device/libhogman.a" -headers "$out_dir/device/headers" \
    -library "$out_dir/sim/libhogman.a" -headers "$out_dir/sim/headers" \
    -output "$out_dir/HogmanCore.xcframework"

  ls -lh "$out_dir/device/libhogman.a" "$out_dir/sim/libhogman.a"
}

case "$TARGET" in
  android) build_android ;;
  ios)     build_ios ;;
  all)     build_android; build_ios ;;
  *)       echo "usage: $0 [android|ios|all]" >&2; exit 2 ;;
esac
