import Foundation
import NetworkExtension

@MainActor
final class TunnelManager: ObservableObject {
    @Published var pens: [PenMeta] = []
    @Published var status: TunnelStatus = .disconnected
    @Published var errorMessage: String?
    @Published var busyMessage: String?

    private var vpnManager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var pollTimer: Timer?

    private let tunnelBundleID = "network.hogman.mobile.tunnel"

    init() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.syncStatusFromManager()
            }
        }
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        pollTimer?.invalidate()
    }

    func bootstrap() async {
        refreshPens()
        #if !targetEnvironment(simulator)
        await loadVPNManager()
        #endif
    }

    func refreshPens() {
        do {
            let dir = try DeviceKeyStore.dataDir()
            pens = try HogmanCoreBridge.listPens(dataDir: dir)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func parseLink(_ raw: String) -> Result<ParsedLink, Error> {
        Result { try HogmanCoreBridge.parseLink(raw) }
    }

    func join(rawLink: String, handle: String, deviceName: String) async throws -> PenMeta {
        let dir = try DeviceKeyStore.dataDir()
        let meta = try await Task.detached(priority: .userInitiated) {
            try HogmanCoreBridge.join(
                dataDir: dir,
                rawLink: rawLink,
                handle: handle,
                deviceName: deviceName
            )
        }.value
        refreshPens()
        return meta
    }

    func connect(zone: String) async {
        errorMessage = nil
        #if targetEnvironment(simulator)
        status = TunnelStatus(
            state: "disconnected",
            zone: zone,
            portal: pens.first(where: { $0.zone == zone })?.portal,
            selfIpv4: nil,
            dnsIp: nil,
            peerRoutes: nil,
            needsLogin: nil,
            error: nil
        )
        errorMessage = "iOS Simulator does not run NEPacketTunnelProvider. Pen enrollment and Keychain storage succeeded; sign with an Apple Developer Organization Team ID on a physical iPhone to start the split tunnel."
        return
        #else
        do {
            let manager = try await ensureVPNManager(zone: zone)
            let session = manager.connection as? NETunnelProviderSession
            status = TunnelStatus(
                state: "connecting",
                zone: zone,
                portal: pens.first(where: { $0.zone == zone })?.portal,
                selfIpv4: nil,
                dnsIp: nil,
                peerRoutes: nil,
                needsLogin: nil,
                error: nil
            )
            try session?.startVPNTunnel()
            startPolling()
        } catch {
            errorMessage = error.localizedDescription
        }
        #endif
    }

    func disconnect() {
        stopPolling()
        vpnManager?.connection.stopVPNTunnel()
        status = .disconnected
    }

    func leave(zone: String, force: Bool) async throws {
        errorMessage = nil
        // When connected to this pen inside the Network Extension process,
        // delegate Leave over app IPC so selfDeleteOverTunnel runs bound to utun.
        if status.state == "connected",
           status.zone == zone,
           let session = vpnManager?.connection as? NETunnelProviderSession {
            let payload = try JSONSerialization.data(withJSONObject: [
                "action": "leave",
                "zone": zone,
                "force": force,
            ])
            let replyData: Data? = try await withCheckedThrowingContinuation { cont in
                do {
                    try session.sendProviderMessage(payload) { resp in
                        cont.resume(returning: resp)
                    }
                } catch {
                    cont.resume(throwing: error)
                }
            }
            if let replyData,
               let obj = try? JSONSerialization.jsonObject(with: replyData) as? [String: Any],
               let ok = obj["ok"] as? Bool,
               !ok {
                throw HogmanError.core((obj["error"] as? String) ?? "Leave failed")
            }
            disconnect()
            refreshPens()
            return
        }

        let dir = try DeviceKeyStore.dataDir()
        try await Task.detached(priority: .userInitiated) {
            try HogmanCoreBridge.leave(dataDir: dir, zone: zone, force: force)
        }.value
        if status.zone == zone {
            disconnect()
        }
        refreshPens()
    }

    private func loadVPNManager() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            vpnManager = managers.first
            syncStatusFromManager()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func ensureVPNManager(zone: String) async throws -> NETunnelProviderManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let manager = managers.first ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = tunnelBundleID
        proto.serverAddress = zone
        proto.providerConfiguration = ["zone": zone]

        manager.protocolConfiguration = proto
        manager.localizedDescription = "Hogman · \(zone)"
        manager.isEnabled = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        vpnManager = manager
        return manager
    }

    private func syncStatusFromManager() {
        guard let manager = vpnManager else {
            status = .disconnected
            stopPolling()
            return
        }
        let zone = (manager.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["zone"] as? String
        switch manager.connection.status {
        case .connected:
            startPolling()
            queryProviderStatus(fallbackZone: zone)
        case .connecting, .reasserting:
            status = TunnelStatus(
                state: "connecting",
                zone: zone,
                portal: zone.map { "https://home.\($0)" },
                selfIpv4: nil,
                dnsIp: nil,
                peerRoutes: nil,
                needsLogin: nil,
                error: nil
            )
            startPolling()
        case .disconnected, .disconnecting, .invalid:
            stopPolling()
            status = .disconnected
        @unknown default:
            stopPolling()
            status = .disconnected
        }
    }

    private func startPolling() {
        pollTimer?.invalidate()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                let zone = (self?.vpnManager?.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerConfiguration?["zone"] as? String
                self?.queryProviderStatus(fallbackZone: zone)
            }
        }
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    private func queryProviderStatus(fallbackZone: String?) {
        guard let session = vpnManager?.connection as? NETunnelProviderSession,
              let msg = "status".data(using: .utf8) else {
            return
        }
        try? session.sendProviderMessage(msg) { [weak self] data in
            guard let data,
                  let env = try? JSONDecoder().decode(ApiEnvelope<TunnelStatus>.self, from: data),
                  let st = env.data else {
                return
            }
            Task { @MainActor in
                self?.status = st
                if st.state == "removed" || st.state == "error" {
                    self?.errorMessage = st.error
                }
            }
        }
    }
}
