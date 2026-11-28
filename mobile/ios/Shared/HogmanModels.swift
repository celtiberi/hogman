import Foundation

public struct ApiEnvelope<T: Decodable>: Decodable {
    public let ok: Bool
    public let error: String?
    public let data: T?
}

public struct EmptyData: Decodable {}

public struct ParsedLink: Decodable, Equatable, Sendable {
    public let host: String
    public let kind: String // "invite" (#t=) or "device" (#k=)
    public let forShare: Bool

    enum CodingKeys: String, CodingKey {
        case host
        case kind
        case forShare = "for_share"
    }
}

public struct PenMeta: Decodable, Equatable, Identifiable, Sendable {
    public var id: String { zone }
    public let zone: String
    public let loginServer: String
    public let portal: String
    public let dnsServer: String
    public let hostname: String
    public let handle: String?

    enum CodingKeys: String, CodingKey {
        case zone
        case loginServer = "login_server"
        case portal
        case dnsServer = "dns_server"
        case hostname
        case handle
    }
}

public struct TunnelReconfig: Decodable, Equatable, Sendable {
    public let zone: String
    public let selfIpv4: String
    public let dnsIp: String
    public let dnsStubIp: String
    public let mtu: Int
    public let peerRoutes: [String]

    enum CodingKeys: String, CodingKey {
        case zone
        case selfIpv4 = "self_ipv4"
        case dnsIp = "dns_ip"
        case dnsStubIp = "dns_stub_ip"
        case mtu
        case peerRoutes = "peer_routes"
    }
}

public struct TunnelStatus: Decodable, Equatable, Sendable {
    public let state: String // "disconnected", "connecting", "connected", "removed", "error"
    public let zone: String?
    public let portal: String?
    public let selfIpv4: String?
    public let dnsIp: String?
    public let peerRoutes: [String]?
    public let needsLogin: Bool?
    public let error: String?

    public var isActive: Bool {
        state == "connecting" || state == "connected"
    }

    public static let disconnected = TunnelStatus(
        state: "disconnected",
        zone: nil,
        portal: nil,
        selfIpv4: nil,
        dnsIp: nil,
        peerRoutes: nil,
        needsLogin: nil,
        error: nil
    )

    enum CodingKeys: String, CodingKey {
        case state
        case zone
        case portal
        case selfIpv4 = "self_ipv4"
        case dnsIp = "dns_ip"
        case peerRoutes = "peer_routes"
        case needsLogin = "needs_login"
        case error
    }
}

public enum HogmanError: LocalizedError, Equatable {
    case core(String)
    case invalidResponse
    case keychain(OSStatus)
    case storage(String)

    public var errorDescription: String? {
        switch self {
        case .core(let msg): return msg
        case .invalidResponse: return "Invalid response from Hogman core."
        case .keychain(let status): return "Keychain error (\(status))."
        case .storage(let msg): return msg
        }
    }
}

public enum HogmanValidation {
    public static let splitDNSStubIP = "100.100.100.100"

    /// Strictly accepts exact IPv4 /32 host routes inside RFC 6598 100.64.0.0/10
    /// (rejects public IPs like 8.8.8.8/32, LAN ranges, 0.0.0.0/0, 100.64.0.0/10,
    /// /24, IPv6, and malformed strings).
    public static func parseHost32Route(_ cidr: String) -> String? {
        let trimmed = cidr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasSuffix("/32") else { return nil }
        let ip = String(trimmed.dropLast(3))
        return isInCgnat10064(ip) ? ip : nil
    }

    public static func isValidIPv4(_ ip: String) -> Bool {
        parseIPv4Octets(ip) != nil
    }

    public static func isInCgnat10064(_ ip: String) -> Bool {
        guard let (a, b, _, _) = parseIPv4Octets(ip) else { return false }
        return a == 100 && (64...127).contains(b)
    }

    private static func parseIPv4Octets(_ ip: String) -> (Int, Int, Int, Int)? {
        let parts = ip.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [Int] = []
        octets.reserveCapacity(4)
        for part in parts {
            guard !part.isEmpty,
                  part.allSatisfy(\.isASCII),
                  part.allSatisfy(\.isNumber),
                  !(part.count > 1 && part.first == "0"),
                  let val = Int(part),
                  (0...255).contains(val) else {
                return nil
            }
            octets.append(val)
        }
        return (octets[0], octets[1], octets[2], octets[3])
    }

    public static func isValidZone(_ zone: String) -> Bool {
        let z = zone.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard (1...253).contains(z.count),
              !z.hasPrefix("."),
              !z.hasSuffix(".") else {
            return false
        }
        let labels = z.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return false }
        for label in labels {
            guard (1...63).contains(label.count),
                  label.first != "-",
                  label.last != "-" else {
                return false
            }
            for ch in label {
                guard ch.isASCII && (ch.isLowercase || ch.isNumber || ch == "-") else {
                    return false
                }
            }
        }
        return true
    }

    /// Always constructs the canonical `https://home.<zone>` URL from a strictly
    /// validated pen zone, ignoring any untrusted server-supplied portal URL.
    public static func homeURL(forZone zone: String) -> URL? {
        let normalized = zone.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard isValidZone(normalized) else { return nil }
        return URL(string: "https://home.\(normalized)")
    }

    public static func validateTunnelReconfig(
        _ cfg: TunnelReconfig,
        expectedZone: String? = nil
    ) -> [String]? {
        let zone = cfg.zone.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard isValidZone(zone) else { return nil }
        if let expected = expectedZone?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
           !expected.isEmpty,
           zone != expected {
            return nil
        }
        guard isInCgnat10064(cfg.selfIpv4),
              cfg.dnsStubIp == splitDNSStubIP,
              (1280...9000).contains(cfg.mtu) else {
            return nil
        }
        var routes: [String] = []
        routes.reserveCapacity(cfg.peerRoutes.count)
        for cidr in cfg.peerRoutes {
            guard let host = parseHost32Route(cidr) else { return nil }
            routes.append(host)
        }
        return routes.isEmpty ? nil : routes
    }

    /// Accepts only Darwin kernel utun interface names ("utun" + 1..6 ASCII digits).
    public static func isValidUtunName(_ name: String) -> Bool {
        guard name.hasPrefix("utun") else { return false }
        let suffix = name.dropFirst(4)
        guard (1...6).contains(suffix.count) else { return false }
        return suffix.allSatisfy { $0.isASCII && $0.isNumber }
    }
}
