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
    private var statusTimer: DispatchSourceTimer?
    private var attachedFD = false
    private var expectedZone: String?
    private var tearingDown = false
    private let stateLock = NSLock()

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let rawZone = proto.providerConfiguration?["zone"] as? String else {
            completionHandler(HogmanError.core("Missing pen zone in VPN configuration."))
            return
        }
        let zone = rawZone.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard HogmanValidation.isValidZone(zone) else {
            completionHandler(HogmanError.core("Invalid pen zone in VPN configuration."))
            return
        }

        let dataDir: String
        do {
            dataDir = try DeviceKeyStore.dataDir()
        } catch {
            completionHandler(error)
            return
        }

        stateLock.lock()
        attachedFD = false
        expectedZone = zone
        tearingDown = false
        stateLock.unlock()

        startPathMonitor()
        startStatusWatchdog()

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
            stopStatusWatchdog()
            stopPathMonitor()
            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        stopStatusWatchdog()
        stopPathMonitor()
        HogmanCoreBridge.stopTunnel()
        stateLock.lock()
        attachedFD = false
        expectedZone = nil
        tearingDown = true
        stateLock.unlock()
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
        stateLock.lock()
        let expected = expectedZone
        stateLock.unlock()

        guard let routes = HogmanValidation.validateTunnelReconfig(cfg, expectedZone: expected) else {
            failAndCancelTunnel("Rejected invalid tunnel reconfiguration.")
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
        let errLock = NSLock()
        var applyErr: Error?
        setTunnelNetworkSettings(settings) { err in
            errLock.lock()
            applyErr = err
            errLock.unlock()
            sem.signal()
        }
        // Keep timeout (4s) strictly below Go StopTunnel's watcher wait (6s) so
        // the callback cannot outlive its Swift context during shutdown.
        guard sem.wait(timeout: .now() + .seconds(4)) == .success else {
            failAndCancelTunnel("Timed out applying tunnel network settings.")
            return -2
        }
        errLock.lock()
        let err = applyErr
        errLock.unlock()
        if let err {
            failAndCancelTunnel("Failed to apply tunnel network settings: \(err.localizedDescription)")
            return -2
        }

        stateLock.lock()
        let alreadyAttached = attachedFD
        stateLock.unlock()
        if alreadyAttached {
            // Routes updated in place; keep existing utun descriptor open.
            return -1
        }

        guard let rawFD = extractUtunFD() else {
            failAndCancelTunnel("Unable to locate utun file descriptor.")
            return -2
        }
        // dup() gives SwappableTUN its own owned descriptor so Close() never
        // double-closes NEPacketTunnelFlow's underlying socket.
        let dupFD = dup(rawFD)
        guard dupFD >= 0 else {
            failAndCancelTunnel("Unable to duplicate utun file descriptor.")
            return -2
        }

        stateLock.lock()
        attachedFD = true
        stateLock.unlock()
        return dupFD
    }

    /// Scans open file descriptors for the kernel `utun` control socket owned by
    /// `NEPacketTunnelFlow`, avoiding private KVC (`socket.fileDescriptor`).
    private func extractUtunFD() -> Int32? {
        var maxFD: Int32 = 1024
        var limit = rlimit()
        if getrlimit(RLIMIT_NOFILE, &limit) == 0, limit.rlim_cur > 0 {
            maxFD = Int32(min(limit.rlim_cur, 4096))
        }
        var nameBuf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        for fd in Int32(0)..<maxFD {
            var ss = sockaddr_storage()
            var ssLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let peerRC = withUnsafeMutablePointer(to: &ss) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    getpeername(fd, sa, &ssLen)
                }
            }
            guard peerRC == 0, ss.ss_family == UInt8(AF_SYSTEM) else {
                continue
            }
            var nameLen = socklen_t(nameBuf.count)
            nameBuf[0] = 0
            // SYSPROTO_CONTROL = 2, UTUN_OPT_IFNAME = 2
            guard getsockopt(fd, 2, 2, &nameBuf, &nameLen) == 0, nameLen > 0 else {
                continue
            }
            nameBuf[nameBuf.count - 1] = 0
            let name = String(cString: nameBuf)
            if HogmanValidation.isValidUtunName(name) {
                return fd
            }
        }
        return nil
    }

    private func failAndCancelTunnel(_ reason: String) {
        stateLock.lock()
        if tearingDown {
            stateLock.unlock()
            return
        }
        tearingDown = true
        stateLock.unlock()

        monitorQueue.async { [weak self] in
            guard let self else { return }
            self.stopStatusWatchdog()
            self.stopPathMonitor()
            self.cancelTunnelWithError(HogmanError.core(reason))
        }
    }

    private func startStatusWatchdog() {
        stopStatusWatchdog()
        let timer = DispatchSource.makeTimerSource(queue: monitorQueue)
        timer.schedule(deadline: .now() + .seconds(5), repeating: .seconds(5))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let st = HogmanCoreBridge.status()
            if st.state == "removed" || st.state == "error" {
                self.failAndCancelTunnel(st.error ?? "Tunnel stopped (\(st.state)).")
            }
        }
        timer.resume()
        statusTimer = timer
    }

    private func stopStatusWatchdog() {
        statusTimer?.cancel()
        statusTimer = nil
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
