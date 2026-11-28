import XCTest
@testable import Hogman

final class HogmanModelsTests: XCTestCase {
    func testParseHost32RouteStrictlyEnforces10064CgnatRange() {
        XCTAssertEqual(HogmanValidation.parseHost32Route("100.64.0.0/32"), "100.64.0.0")
        XCTAssertEqual(HogmanValidation.parseHost32Route("100.64.0.1/32"), "100.64.0.1")
        XCTAssertEqual(HogmanValidation.parseHost32Route("100.100.100.100/32"), "100.100.100.100")
        XCTAssertEqual(HogmanValidation.parseHost32Route("100.127.255.255/32"), "100.127.255.255")

        // Public, carrier, LAN, and boundary-adjacent IPs MUST be rejected.
        XCTAssertNil(HogmanValidation.parseHost32Route("8.8.8.8/32"))
        XCTAssertNil(HogmanValidation.parseHost32Route("1.1.1.1/32"))
        XCTAssertNil(HogmanValidation.parseHost32Route("192.168.1.1/32"))
        XCTAssertNil(HogmanValidation.parseHost32Route("100.63.255.255/32"))
        XCTAssertNil(HogmanValidation.parseHost32Route("100.128.0.0/32"))
        XCTAssertNil(HogmanValidation.parseHost32Route("100.064.0.1/32"))

        // Broad prefixes, non-/32, IPv6, and malformed strings MUST be rejected.
        XCTAssertNil(HogmanValidation.parseHost32Route("0.0.0.0/0"))
        XCTAssertNil(HogmanValidation.parseHost32Route("100.64.0.0/10"))
        XCTAssertNil(HogmanValidation.parseHost32Route("100.64.0.1/24"))
        XCTAssertNil(HogmanValidation.parseHost32Route("100.64.0.1"))
        XCTAssertNil(HogmanValidation.parseHost32Route("999.0.0.1/32"))
        XCTAssertNil(HogmanValidation.parseHost32Route("fd7a:115c:a1e0::1/128"))
    }

    func testValidateTunnelReconfigRejectsOutOfRangeAndMismatchedZone() {
        let valid = TunnelReconfig(
            zone: "bobo.pens.example.com",
            selfIpv4: "100.64.0.12",
            dnsIp: "100.64.0.1",
            dnsStubIp: "100.100.100.100",
            mtu: 1280,
            peerRoutes: ["100.64.0.1/32", "100.100.100.100/32"]
        )
        XCTAssertEqual(
            HogmanValidation.validateTunnelReconfig(valid, expectedZone: "bobo.pens.example.com"),
            ["100.64.0.1", "100.100.100.100"]
        )

        // Mismatched zone rejected.
        XCTAssertNil(HogmanValidation.validateTunnelReconfig(valid, expectedZone: "other.pens.example.com"))

        // Even one public /32 route alongside valid pen routes rejects the entire reconfig.
        let hijackedRoute = TunnelReconfig(
            zone: "bobo.pens.example.com",
            selfIpv4: "100.64.0.12",
            dnsIp: "100.64.0.1",
            dnsStubIp: "100.100.100.100",
            mtu: 1280,
            peerRoutes: ["100.64.0.1/32", "8.8.8.8/32"]
        )
        XCTAssertNil(HogmanValidation.validateTunnelReconfig(hijackedRoute))

        // Out-of-range selfIpv4 rejected.
        let badSelf = TunnelReconfig(
            zone: "bobo.pens.example.com",
            selfIpv4: "192.168.1.10",
            dnsIp: "100.64.0.1",
            dnsStubIp: "100.100.100.100",
            mtu: 1280,
            peerRoutes: ["100.64.0.1/32"]
        )
        XCTAssertNil(HogmanValidation.validateTunnelReconfig(badSelf))

        // Non-canonical dnsStubIp rejected.
        let badStub = TunnelReconfig(
            zone: "bobo.pens.example.com",
            selfIpv4: "100.64.0.12",
            dnsIp: "100.64.0.1",
            dnsStubIp: "8.8.8.8",
            mtu: 1280,
            peerRoutes: ["100.64.0.1/32"]
        )
        XCTAssertNil(HogmanValidation.validateTunnelReconfig(badStub))

        let broad = TunnelReconfig(
            zone: "bobo.pens.example.com",
            selfIpv4: "100.64.0.12",
            dnsIp: "100.64.0.1",
            dnsStubIp: "100.100.100.100",
            mtu: 1280,
            peerRoutes: ["100.64.0.0/10"]
        )
        XCTAssertNil(HogmanValidation.validateTunnelReconfig(broad))

        let badMtu = TunnelReconfig(
            zone: "bobo.pens.example.com",
            selfIpv4: "100.64.0.12",
            dnsIp: "100.64.0.1",
            dnsStubIp: "100.100.100.100",
            mtu: 500,
            peerRoutes: ["100.64.0.1/32"]
        )
        XCTAssertNil(HogmanValidation.validateTunnelReconfig(badMtu))
    }

    func testHomeURLAlwaysBuildsCanonicalHttpsFromValidatedZone() {
        XCTAssertEqual(
            HogmanValidation.homeURL(forZone: "Bobo.Pens.Example.Com")?.absoluteString,
            "https://home.bobo.pens.example.com"
        )
        XCTAssertNil(HogmanValidation.homeURL(forZone: ""))
        XCTAssertNil(HogmanValidation.homeURL(forZone: "localhost"))
        XCTAssertNil(HogmanValidation.homeURL(forZone: "tel:911"))
        XCTAssertNil(HogmanValidation.homeURL(forZone: "bobo.example.com/evil"))
        XCTAssertNil(HogmanValidation.homeURL(forZone: "bobo.example.com:8443"))
        XCTAssertNil(HogmanValidation.homeURL(forZone: "bobo.example.com@attacker.com"))
    }

    func testIsValidUtunNameRejectsNonUtunNames() {
        XCTAssertTrue(HogmanValidation.isValidUtunName("utun0"))
        XCTAssertTrue(HogmanValidation.isValidUtunName("utun42"))
        XCTAssertFalse(HogmanValidation.isValidUtunName("utun"))
        XCTAssertFalse(HogmanValidation.isValidUtunName("en0"))
        XCTAssertFalse(HogmanValidation.isValidUtunName("utun0a"))
        XCTAssertFalse(HogmanValidation.isValidUtunName("utun1234567"))
    }

    func testCoreBridgeParseLinkAndListPensLive() throws {
        let parsed = try HogmanCoreBridge.parseLink("https://bobo.gate.example.com/join#t=exampletoken")
        XCTAssertEqual(parsed.host, "bobo.gate.example.com")
        XCTAssertEqual(parsed.kind, "invite")
        XCTAssertFalse(parsed.forShare)

        XCTAssertThrowsError(try HogmanCoreBridge.parseLink("https://bobo.gate.example.com/join#k=key&for=share"))
        XCTAssertThrowsError(try HogmanCoreBridge.parseLink("hogman://join#t=exampletoken"))

        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("hogman-ios-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let pens = try HogmanCoreBridge.listPens(dataDir: tmpDir.path)
        XCTAssertTrue(pens.isEmpty)
    }
}
