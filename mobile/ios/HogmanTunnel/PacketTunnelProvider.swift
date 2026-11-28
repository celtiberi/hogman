import Darwin
import Foundation
import Network
import NetworkExtension

/// iOS NEPacketTunnelProvider backed by libhogman.
///
/// Configures domain-matched split DNS (`matchDomains = [zone]`,
/// `matchDomainsNoSearch = true`) and installs ONLY exact `/32` routes for active
/// `tag:infra` and `tag:server` pen peers plus `100.100.100.100/32`. Regular
/// internet browsing and non-pen DNS never enter the extension.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let monitorQueue = DispatchQueue(label: "network.hogman.mobile.pathmonitor")
    private var pathMonitor: NWPathMonitor?
    private var attachedFD = false
    private let fdLock = NSLock()

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let zone = proto.providerConfiguration?["zone"] as? String,
              !zone.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            completionHandler(HogmanError.core("Missing pen zone in VPN configuration."))
            return
        }

        let dataDir: String
        do {
            dataDir = try DeviceKeyStore.dataDir()
        } catch {
            completionHandler(error)
            return
        }

        fdLock.lock()
        attachedFD = false
        fdLock.unlock()

        startPathMonitor()

        do {
            _ = try HogmanCoreBridge.startTunnel(
                dataDir: dataDir,
                zone: zone,
                mtu: 1280,
                upstreamDNSJSON: "[]"
            ) { [weak self] cfg in
                guard let self else { return -2 }
                return self.applyNetworkSettings(cfg)
            }
            completionHandler(nil)
        } catch {
            stopPathMonitor()
            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        stopPathMonitor()
        HogmanCoreBridge.stopTunnel()
        fdLock.lock()
        attachedFD = false
        fdLock.unlock()
        completionHandler()
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        if let req = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
           let action = req["action"] as? String,
           action == "leave",
           let zone = req["zone"] as? String {
            let force = (req["force"] as? Bool) ?? false
            do {
                let dataDir = try DeviceKeyStore.dataDir()
                try HogmanCoreBridge.leave(dataDir: dataDir, zone: zone, force: force)
                let ok = #"{"ok":true}"#.data(using: .utf8)
                completionHandler?(ok)
                cancelTunnelWithError(nil)
            } catch {
                let errObj: [String: Any] = ["ok": false, "error": error.localizedDescription]
                let data = try? JSONSerialization.data(withJSONObject: errObj)
                completionHandler?(data)
            }
            return
        }
        let json = HogmanCoreBridge.statusJSON()
        completionHandler?(json.data(using: .utf8))
    }

    private func applyNetworkSettings(_ cfg: TunnelReconfig) -> Int32 {
        guard let routes = HogmanValidation.validateTunnelReconfig(cfg) else {
            return -2
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: cfg.mtu)

        let ipv4 = NEIPv4Settings(addresses: [cfg.selfIpv4], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = routes.map { ip in
            NEIPv4Route(destinationAddress: ip, subnetMask: "255.255.255.255")
        }
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: [cfg.dnsStubIp])
        dns.matchDomains = [cfg.zone]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns

        let sem = DispatchSemaphore(value: 0)
        var applyErr: Error?
        setTunnelNetworkSettings(settings) { err in
            applyErr = err
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + .seconds(10))
        if applyErr != nil {
            return -2
        }

        fdLock.lock()
        let alreadyAttached = attachedFD
        fdLock.unlock()
        if alreadyAttached {
            // Routes updated in place; keep existing utun descriptor open.
            return -1
        }

        guard let rawFD = extractUtunFD() else {
            return -2
        }
        // dup() gives SwappableTUN its own owned descriptor so Close() never
        // double-closes NEPacketTunnelFlow's underlying socket.
        let dupFD = dup(rawFD)
        guard dupFD >= 0 else {
            return -2
        }

        fdLock.lock()
        attachedFD = true
        fdLock.unlock()
        return dupFD
    }

    private func extractUtunFD() -> Int32? {
        if let fd = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32, fd >= 0 {
            return fd
        }
        if let num = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? NSNumber, num.int32Value >= 0 {
            return num.int32Value
        }
        return nil
    }

    private func startPathMonitor() {
        stopPathMonitor()
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { _ in
            try? HogmanCoreBridge.updateNetwork(upstreamDNSJSON: "[]", linkChanged: true)
        }
        monitor.start(queue: monitorQueue)
        pathMonitor = monitor
    }

    private func stopPathMonitor() {
        pathMonitor?.cancel()
        pathMonitor = nil
    }
}
