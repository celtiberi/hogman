package network.hogman.mobile.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HogmanModelsTest {

    @Test
    fun decodeParsedLinkAcceptsInviteAndDeviceLinks() {
        val raw = """{"ok":true,"data":{"host":"bobo.gate.example.com","kind":"invite","for_share":false}}"""
        val res = HogmanModels.decodeParsedLink(raw) as ApiResult.Ok
        assertEquals("bobo.gate.example.com", res.data.host)
        assertEquals("invite", res.data.kind)
        assertFalse(res.data.forShare)
    }

    @Test
    fun decodeEnvelopeSurfacesErrorMessage() {
        val raw = """{"ok":false,"error":"handle already taken"}"""
        val res = HogmanModels.decodePenMeta(raw) as ApiResult.Err
        assertEquals("handle already taken", res.message)
    }

    @Test
    fun decodePenListCanonicalizesPortalFromZoneIgnoringHostileServerURL() {
        val raw = """
            {
              "ok": true,
              "data": [
                {
                  "zone": "bobo.pens.example.com",
                  "login_server": "https://bobo.gate.example.com",
                  "portal": "market://details?id=evil",
                  "dns_server": "100.64.0.1",
                  "hostname": "pixel",
                  "handle": "alice"
                }
              ]
            }
        """.trimIndent()
        val res = HogmanModels.decodePenList(raw) as ApiResult.Ok
        assertEquals(1, res.data.size)
        assertEquals("bobo.pens.example.com", res.data[0].zone)
        assertEquals("https://home.bobo.pens.example.com", res.data[0].portal)
    }

    @Test
    fun homeUrlForZoneRejectsSchemesPathsAndMalformedZones() {
        assertEquals("https://home.bobo.pens.example.com", HogmanModels.homeUrlForZone("bobo.pens.example.com"))
        assertNull(HogmanModels.homeUrlForZone("tel:911"))
        assertNull(HogmanModels.homeUrlForZone("market://details?id=evil"))
        assertNull(HogmanModels.homeUrlForZone("intent://foo#Intent;end"))
        assertNull(HogmanModels.homeUrlForZone("bobo.pens.example.com/evil"))
        assertNull(HogmanModels.homeUrlForZone("bobo..example.com"))
        assertNull(HogmanModels.homeUrlForZone("localhost"))
        assertNull(HogmanModels.homeUrlForZone(""))
    }

    @Test
    fun parseHost32RouteStrictlyEnforces10064CGNATAnd32Prefix() {
        assertEquals("100.64.0.1", HogmanModels.parseHost32Route("100.64.0.1/32"))
        assertEquals("100.100.100.100", HogmanModels.parseHost32Route("100.100.100.100/32"))
        assertEquals("100.127.255.254", HogmanModels.parseHost32Route("100.127.255.254/32"))

        // Public IPs, LAN IPs, CGNAT boundaries, broad prefixes, and IPv6 must all be rejected.
        assertNull(HogmanModels.parseHost32Route("8.8.8.8/32"))
        assertNull(HogmanModels.parseHost32Route("1.1.1.1/32"))
        assertNull(HogmanModels.parseHost32Route("192.168.1.1/32"))
        assertNull(HogmanModels.parseHost32Route("100.63.255.255/32"))
        assertNull(HogmanModels.parseHost32Route("100.128.0.0/32"))
        assertNull(HogmanModels.parseHost32Route("0.0.0.0/0"))
        assertNull(HogmanModels.parseHost32Route("100.64.0.0/10"))
        assertNull(HogmanModels.parseHost32Route("100.64.0.1/24"))
        assertNull(HogmanModels.parseHost32Route("100.64.0.1"))
        assertNull(HogmanModels.parseHost32Route("999.0.0.1/32"))
        assertNull(HogmanModels.parseHost32Route("fd7a:115c:a1e0::1/128"))
    }

    @Test
    fun decodeTunnelReconfigRejectsEntirePayloadOnOutOfRangeRouteSelfOrStub() {
        val okJson = """
            {
              "zone": "bobo.pens.example.com",
              "self_ipv4": "100.64.0.12",
              "dns_ip": "100.64.0.1",
              "dns_stub_ip": "100.100.100.100",
              "mtu": 1280,
              "peer_routes": ["100.64.0.1/32", "100.100.100.100/32"]
            }
        """.trimIndent()
        val cfg = HogmanModels.decodeTunnelReconfig(okJson)!!
        assertEquals("100.64.0.12", cfg.selfIpv4)
        assertEquals(2, cfg.peerRoutes.size)

        // Single public route must reject the ENTIRE reconfig.
        assertNull(HogmanModels.decodeTunnelReconfig(okJson.replace("100.64.0.1/32", "8.8.8.8/32")))
        // Out-of-range self_ipv4 must reject the ENTIRE reconfig.
        assertNull(HogmanModels.decodeTunnelReconfig(okJson.replace("100.64.0.12", "8.8.4.4")))
        // Non-100.100.100.100 DNS stub must reject the ENTIRE reconfig.
        assertNull(HogmanModels.decodeTunnelReconfig(okJson.replace("\"dns_stub_ip\": \"100.100.100.100\"", "\"dns_stub_ip\": \"100.64.0.99\"")))
        // Invalid MTU must reject.
        assertNull(HogmanModels.decodeTunnelReconfig(okJson.replace("1280", "500")))
        // Empty peer routes must reject.
        assertNull(HogmanModels.decodeTunnelReconfig(okJson.replace("""["100.64.0.1/32", "100.100.100.100/32"]""", "[]")))
    }

    @Test
    fun encodeUpstreamDnsJsonSerializesCleanArray() {
        val json = HogmanModels.encodeUpstreamDnsJson(listOf("10.0.2.3", " ", "1.1.1.1"))
        assertEquals("""["10.0.2.3","1.1.1.1"]""", json)
        assertTrue(HogmanModels.isValidIpv4("10.0.2.3"))
        assertFalse(HogmanModels.isValidIpv4("256.0.0.1"))
    }
}
