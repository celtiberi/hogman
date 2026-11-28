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
    fun decodePenListParsesSortedPens() {
        val raw = """
            {
              "ok": true,
              "data": [
                {
                  "zone": "bobo.pens.example.com",
                  "login_server": "https://bobo.gate.example.com",
                  "portal": "https://home.bobo.pens.example.com",
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
    fun parseHost32RouteStrictlyRejectsBroadPrefixes() {
        assertEquals("100.64.0.1", HogmanModels.parseHost32Route("100.64.0.1/32"))
        assertEquals("100.100.100.100", HogmanModels.parseHost32Route("100.100.100.100/32"))

        // Broad routes, IPv6, and malformed strings must all be rejected.
        assertNull(HogmanModels.parseHost32Route("0.0.0.0/0"))
        assertNull(HogmanModels.parseHost32Route("100.64.0.0/10"))
        assertNull(HogmanModels.parseHost32Route("100.64.0.1/24"))
        assertNull(HogmanModels.parseHost32Route("100.64.0.1"))
        assertNull(HogmanModels.parseHost32Route("999.0.0.1/32"))
        assertNull(HogmanModels.parseHost32Route("fd7a:115c:a1e0::1/128"))
    }

    @Test
    fun decodeTunnelReconfigValidatesMtuAndAddresses() {
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

        val badMtu = okJson.replace("1280", "500")
        assertNull(HogmanModels.decodeTunnelReconfig(badMtu))
    }

    @Test
    fun encodeUpstreamDnsJsonSerializesCleanArray() {
        val json = HogmanModels.encodeUpstreamDnsJson(listOf("10.0.2.3", " ", "1.1.1.1"))
        assertEquals("""["10.0.2.3","1.1.1.1"]""", json)
        assertTrue(HogmanModels.isValidIpv4("10.0.2.3"))
        assertFalse(HogmanModels.isValidIpv4("256.0.0.1"))
    }
}
