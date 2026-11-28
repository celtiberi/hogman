import Foundation
import HogmanCore

public final class TunnelReconfigBox {
    let handler: (TunnelReconfig) -> Int32

    public init(handler: @escaping (TunnelReconfig) -> Int32) {
        self.handler = handler
    }
}

private func cReconfigTrampoline(
    _ reconfigJSON: UnsafePointer<CChar>?,
    _ userData: UnsafeMutableRawPointer?
) -> Int32 {
    guard let reconfigJSON, let userData else { return -2 }
    let box = Unmanaged<TunnelReconfigBox>.fromOpaque(userData).takeUnretainedValue()
    let str = String(cString: reconfigJSON)
    guard let data = str.data(using: .utf8),
          let cfg = try? JSONDecoder().decode(TunnelReconfig.self, from: data) else {
        return -2
    }
    return box.handler(cfg)
}

/// Safe Swift boundary over libhogman's 9-function C-ABI.
public enum HogmanCoreBridge {
    private static let lock = NSLock()
    private static var activeReconfigBox: Unmanaged<TunnelReconfigBox>?

    public static func parseLink(_ rawLink: String) throws -> ParsedLink {
        let json = rawLink.withCString { cLink in
            takeCString(hogman_parse_link(UnsafeMutablePointer(mutating: cLink)))
        }
        return try decodeEnvelope(json, as: ParsedLink.self)
    }

    public static func join(
        dataDir: String,
        rawLink: String,
        handle: String,
        deviceName: String,
        controlCAPEM: String = ""
    ) throws -> PenMeta {
        let json: String = try DeviceKeyStore.withStateKey { keyPtr, keyLen in
            dataDir.withCString { cDir in
                rawLink.withCString { cLink in
                    handle.withCString { cHandle in
                        deviceName.withCString { cDev in
                            controlCAPEM.withCString { cCA in
                                takeCString(
                                    hogman_join(
                                        UnsafeMutablePointer(mutating: cDir),
                                        UnsafeMutablePointer(mutating: keyPtr),
                                        keyLen,
                                        UnsafeMutablePointer(mutating: cLink),
                                        UnsafeMutablePointer(mutating: cHandle),
                                        UnsafeMutablePointer(mutating: cDev),
                                        UnsafeMutablePointer(mutating: cCA)
                                    )
                                )
                            }
                        }
                    }
                }
            }
        }
        return try decodeEnvelope(json, as: PenMeta.self)
    }

    public static func listPens(dataDir: String) throws -> [PenMeta] {
        let json = dataDir.withCString { cDir in
            takeCString(hogman_list_pens(UnsafeMutablePointer(mutating: cDir)))
        }
        return try decodeEnvelope(json, as: [PenMeta].self)
    }

    public static func startTunnel(
        dataDir: String,
        zone: String,
        mtu: Int32 = 1280,
        upstreamDNSJSON: String = "[]",
        onReconfig: @escaping (TunnelReconfig) -> Int32
    ) throws -> TunnelStatus {
        let newBox = Unmanaged.passRetained(TunnelReconfigBox(handler: onReconfig))

        // Stop any previous tunnel first so old Go goroutines exit before releasing the old box.
        _ = takeCString(hogman_stop_tunnel())

        lock.lock()
        let oldBox = activeReconfigBox
        activeReconfigBox = newBox
        lock.unlock()
        oldBox?.release()

        do {
            let json: String = try DeviceKeyStore.withStateKey { keyPtr, keyLen in
                dataDir.withCString { cDir in
                    zone.withCString { cZone in
                        upstreamDNSJSON.withCString { cDNS in
                            takeCString(
                                hogman_start_tunnel(
                                    UnsafeMutablePointer(mutating: cDir),
                                    UnsafeMutablePointer(mutating: keyPtr),
                                    keyLen,
                                    UnsafeMutablePointer(mutating: cZone),
                                    mtu,
                                    UnsafeMutablePointer(mutating: cDNS),
                                    nil,
                                    cReconfigTrampoline,
                                    newBox.toOpaque()
                                )
                            )
                        }
                    }
                }
            }
            return try decodeEnvelope(json, as: TunnelStatus.self)
        } catch {
            // Stop any partially started tunnel before releasing the callback context.
            _ = takeCString(hogman_stop_tunnel())
            lock.lock()
            let failedBox = activeReconfigBox
            activeReconfigBox = nil
            lock.unlock()
            failedBox?.release()
            throw error
        }
    }

    public static func updateNetwork(upstreamDNSJSON: String = "[]", linkChanged: Bool) throws {
        let json = upstreamDNSJSON.withCString { cDNS in
            takeCString(hogman_update_network(UnsafeMutablePointer(mutating: cDNS), linkChanged ? 1 : 0))
        }
        _ = try decodeUnitEnvelope(json)
    }

    public static func statusJSON() -> String {
        takeCString(hogman_status())
    }

    public static func status() -> TunnelStatus {
        let json = statusJSON()
        return (try? decodeEnvelope(json, as: TunnelStatus.self)) ?? .disconnected
    }

    @discardableResult
    public static func stopTunnel() -> TunnelStatus {
        let json = takeCString(hogman_stop_tunnel())
        lock.lock()
        let oldBox = activeReconfigBox
        activeReconfigBox = nil
        lock.unlock()
        oldBox?.release()
        return (try? decodeEnvelope(json, as: TunnelStatus.self)) ?? .disconnected
    }

    public static func leave(dataDir: String, zone: String, force: Bool) throws {
        let json: String = try DeviceKeyStore.withStateKey { keyPtr, keyLen in
            dataDir.withCString { cDir in
                zone.withCString { cZone in
                    takeCString(
                        hogman_leave(
                            UnsafeMutablePointer(mutating: cDir),
                            UnsafeMutablePointer(mutating: keyPtr),
                            keyLen,
                            UnsafeMutablePointer(mutating: cZone),
                            force ? 1 : 0
                        )
                    )
                }
            }
        }
        _ = try decodeUnitEnvelope(json)
    }

    private static func takeCString(_ ptr: UnsafeMutablePointer<CChar>?) -> String {
        guard let ptr else {
            return #"{"ok":false,"error":"null native response"}"#
        }
        defer { hogman_free(ptr) }
        return String(cString: ptr)
    }

    private static func decodeEnvelope<T: Decodable>(_ raw: String, as type: T.Type) throws -> T {
        guard let data = raw.data(using: .utf8),
              let env = try? JSONDecoder().decode(ApiEnvelope<T>.self, from: data) else {
            throw HogmanError.invalidResponse
        }
        if !env.ok {
            throw HogmanError.core(env.error ?? "Unknown Hogman error")
        }
        guard let payload = env.data else {
            throw HogmanError.invalidResponse
        }
        return payload
    }

    private static func decodeUnitEnvelope(_ raw: String) throws {
        guard let data = raw.data(using: .utf8),
              let env = try? JSONDecoder().decode(ApiEnvelope<EmptyData>.self, from: data) else {
            throw HogmanError.invalidResponse
        }
        if !env.ok {
            throw HogmanError.core(env.error ?? "Unknown Hogman error")
        }
    }
}
