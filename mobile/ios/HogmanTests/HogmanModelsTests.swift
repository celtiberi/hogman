import XCTest
@testable import Hogman

final class HogmanModelsTests: XCTestCase {
    func testParseHost32RouteStrictlyRejectsBroadPrefixes() {
        XCTAssertEqual(HogmanValidation.parseHost32Route("100.64.0.1/32"), "100.64.0.1")
        XCTAssertEqual(HogmanValidation.parseHost32Route("100.100.100.100/32"), "100.100.100.100")

        XCTAssertNil(HogmanValidation.parseHost32Route("0.0.0.0/0"))
        XCTAssertNil(HogmanValidation.parseHost32Route("100.64.0.0/10"))
        XCTAssertNil(HogmanValidation.parseHost32Route("100.64.0.1/24"))
        XCTAssertNil(HogmanValidation.parseHost32Route("100.64.0.1"))
        XCTAssertNil(HogmanValidation.parseHost32Route("999.0.0.1/32"))
        XCTAssertNil(HogmanValidation.parseHost32Route("fd7a:115c:a1e0::1/128"))
    }

    func testValidateTunnelReconfigRejectsInvalidMtuAndBroadRoute() {
        let valid = TunnelReconfig(
            zone: "bobo.pens.example.com",
            selfIpv4: "100.64.0.12",
            dnsIp: "100.64.0.1",
            dnsStubIp: "100.100.100.100",
            mtu: 1280,
            peerRoutes: ["100.64.0.1/32", "100.100.100.100/32"]
        )
        XCTAssertEqual(HogmanValidation.validateTunnelReconfig(valid), ["100.64.0.1", "100.100.100.100"])

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
