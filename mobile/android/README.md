# Hogman Mobile (Android)

Native Kotlin + Jetpack Compose Android client backed by the shared Go core (`core/join/mobile`).

## Prerequisites

- Go 1.25+
- Android SDK (API 36), NDK 28 (`28.2.13676358`), CMake `3.22.1`, JDK 17 or 21

## Build & Test

1. Build the 16 KB page-aligned native Go shared libraries (`arm64-v8a` and `x86_64`) from the repository root:

```sh
mobile/build-core.sh android
```

2. Run JVM unit tests and build the debug APK:

```sh
cd mobile/android
./gradlew testDebugUnitTest assembleDebug
```

The debug APK is written to `mobile/android/app/build/outputs/apk/debug/app-debug.apk`.

## Security & Networking Notes

- **Split-tunnel `/32` routes only:** `HogmanVpnService` routes only active `tag:infra` and `tag:server` peer `/32` IPv4 addresses plus `100.100.100.100/32`. Regular internet traffic never enters the VPN.
- **Non-cloneable device keys:** The 32-byte state DEK is wrapped by a non-exportable Android Keystore AES-256-GCM key and stored under `noBackupFilesDir`. Cloud backups and device-to-device transfers are explicitly excluded in `AndroidManifest.xml`, `data_extraction_rules.xml`, and `backup_rules.xml`.
- **Android Private DNS:** Pinning Android Private DNS to a specific DoT hostname bypasses `VpnService` DNS; the app detects strict Private DNS and warns the user to use Automatic or Off while connected.
- **No custom URL scheme:** Join links (`#t=` / `#k=`) are entered via in-app QR scan (CameraX + ZXing, no Play Services) or the explicit Paste button.
