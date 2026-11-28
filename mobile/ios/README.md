# Hogman Mobile (iOS)

Native SwiftUI iOS client + `NEPacketTunnelProvider` Network Extension backed by the shared Go core (`HogmanCore.xcframework`).

## Prerequisites

- macOS with Xcode 16+ (iOS 16.0+ deployment target)
- Go 1.25+

## Build & Test on Simulator (No Developer Account Required)

1. Build `HogmanCore.xcframework` (`iphoneos` arm64 + `iphonesimulator` arm64) from the repository root:

```sh
mobile/build-core.sh ios
```

2. Build both targets (`Hogman` app and `HogmanTunnel` extension) and run XCTests on the iOS Simulator:

```sh
cd mobile/ios
xcodebuild -project Hogman.xcodeproj -scheme Hogman \
  -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build
```

## Enabling Live `NEPacketTunnelProvider` on a Physical iPhone

iOS Simulator does not run `NEPacketTunnelProvider` extensions. Once your Apple Developer Organization account is active:

1. In Apple Developer Portal, register App IDs `network.hogman.mobile` and `network.hogman.mobile.tunnel` with the **Network Extensions (Packet Tunnel)** and **App Groups** (`group.network.hogman.mobile`) capabilities.
2. Open `mobile/ios/Hogman.xcodeproj` in Xcode, set `DEVELOPMENT_TEAM` on both `Hogman` and `HogmanTunnel` targets, and build/archive for a physical iPhone or TestFlight.

## Security & Networking Notes

- **Domain-matched split DNS + per-peer `/32` routes only:** `PacketTunnelProvider` sets `NEDNSSettings.matchDomains = [zone]` (`matchDomainsNoSearch = true`) and installs only exact `/32` routes for active `tag:infra` and `tag:server` peers plus `100.100.100.100/32`. Non-pen DNS and internet traffic never enter the extension.
- **Non-cloneable device keys:** The 32-byte state DEK is stored in iOS Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` inside the shared Keychain Access Group and explicitly zeroed after every C-ABI call. The shared App Group state directory is marked `NSURLIsExcludedFromBackupKey = true`.
- **No custom URL scheme:** Join links (`#t=` / `#k=`) are entered via the native `AVCaptureSession` QR scanner or the explicit Paste button.
