package network.hogman.mobile.core

import org.json.JSONArray
import org.json.JSONObject

sealed interface ApiResult<out T> {
    data class Ok<T>(val data: T) : ApiResult<T>
    data class Err(val message: String) : ApiResult<Nothing>
}

data class ParsedLink(
    val host: String,
    val kind: String, // "invite" (#t=) or "device" (#k=)
    val forShare: Boolean,
)

data class PenMeta(
    val zone: String,
    val loginServer: String,
    val portal: String,
    val dnsServer: String,
    val hostname: String,
    val handle: String,
)

data class TunnelReconfig(
    val zone: String,
    val selfIpv4: String,
    val dnsIp: String,
    val dnsStubIp: String,
    val mtu: Int,
    val peerRoutes: List<String>,
)

data class TunnelStatus(
    val state: String, // "disconnected", "connecting", "connected", "removed", "error"
    val zone: String = "",
    val portal: String = "",
    val selfIpv4: String = "",
    val dnsIp: String = "",
    val peerRoutes: List<String> = emptyList(),
    val needsLogin: Boolean = false,
    val error: String = "",
) {
    val isActive: Boolean
        get() = state == "connecting" || state == "connected"

    companion object {
        val Disconnected = TunnelStatus(state = "disconnected")
    }
}

object HogmanModels {
    const val SPLIT_DNS_STUB_IP = "100.100.100.100"

    private val ipv4Regex = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""")
    private val dnsLabelRegex = Regex("""^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$""")

    fun decodeParsedLink(rawJson: String): ApiResult<ParsedLink> =
        decodeObjectEnvelope(rawJson) { obj ->
            ParsedLink(
                host = obj.optString("host", ""),
                kind = obj.optString("kind", ""),
                forShare = obj.optBoolean("for_share", false),
            )
        }

    fun decodePenMeta(rawJson: String): ApiResult<PenMeta> =
        decodeObjectEnvelope(rawJson) { parsePenMeta(it) }

    fun decodePenList(rawJson: String): ApiResult<List<PenMeta>> {
        val env = parseEnvelope(rawJson) ?: return ApiResult.Err("invalid native JSON response")
        if (!env.optBoolean("ok", false)) {
            return ApiResult.Err(env.optString("error", "unknown error"))
        }
        val arr = env.optJSONArray("data") ?: return ApiResult.Ok(emptyList())
        val out = ArrayList<PenMeta>(arr.length())
        for (i in 0 until arr.length()) {
            val item = arr.optJSONObject(i) ?: continue
            val meta = parsePenMeta(item)
            if (isValidZone(meta.zone)) {
                out.add(meta)
            }
        }
        return ApiResult.Ok(out)
    }

    fun decodeTunnelStatus(rawJson: String): ApiResult<TunnelStatus> =
        decodeObjectEnvelope(rawJson) { obj ->
            val zone = obj.optString("zone", "").trim().lowercase()
            TunnelStatus(
                state = obj.optString("state", "disconnected"),
                zone = zone,
                portal = homeUrlForZone(zone).orEmpty(),
                selfIpv4 = obj.optString("self_ipv4", ""),
                dnsIp = obj.optString("dns_ip", ""),
                peerRoutes = readStringList(obj.optJSONArray("peer_routes")),
                needsLogin = obj.optBoolean("needs_login", false),
                error = obj.optString("error", ""),
            )
        }

    fun decodeUnit(rawJson: String): ApiResult<Unit> {
        val env = parseEnvelope(rawJson) ?: return ApiResult.Err("invalid native JSON response")
        if (!env.optBoolean("ok", false)) {
            return ApiResult.Err(env.optString("error", "unknown error"))
        }
        return ApiResult.Ok(Unit)
    }

    /**
     * Strictly validates a TunnelReconfig before applying OS VPN settings.
     * Rejects the entire reconfig if:
     *  - zone is invalid,
     *  - selfIpv4 is outside RFC 6598 (100.64.0.0/10),
     *  - dnsStubIp is not exactly 100.100.100.100,
     *  - mtu is outside [1280, 9000], or
     *  - peerRoutes is empty or contains ANY route that is not an exact /32
     *    inside 100.64.0.0/10.
     */
    fun decodeTunnelReconfig(rawJson: String): TunnelReconfig? {
        val obj = parseEnvelope(rawJson) ?: return null
        val zone = obj.optString("zone", "").trim().lowercase()
        val selfIpv4 = obj.optString("self_ipv4", "").trim()
        val dnsStubIp = obj.optString("dns_stub_ip", "").trim()
        val mtu = obj.optInt("mtu", 1280)
        if (!isValidZone(zone) || !isInCgnat10064(selfIpv4) || dnsStubIp != SPLIT_DNS_STUB_IP) {
            return null
        }
        if (mtu < 1280 || mtu > 9000) {
            return null
        }
        val rawRoutes = readStringList(obj.optJSONArray("peer_routes"))
        if (rawRoutes.isEmpty()) {
            return null
        }
        for (cidr in rawRoutes) {
            if (parseHost32Route(cidr) == null) {
                return null
            }
        }
        return TunnelReconfig(
            zone = zone,
            selfIpv4 = selfIpv4,
            dnsIp = obj.optString("dns_ip", "").trim(),
            dnsStubIp = dnsStubIp,
            mtu = mtu,
            peerRoutes = rawRoutes,
        )
    }

    /**
     * Strictly accepts exact IPv4 /32 host routes inside RFC 6598 (100.64.0.0/10)
     * only, rejecting broad prefixes and public/LAN addresses.
     */
    fun parseHost32Route(cidr: String): String? {
        val trimmed = cidr.trim()
        if (!trimmed.endsWith("/32")) {
            return null
        }
        val ip = trimmed.removeSuffix("/32")
        return if (isInCgnat10064(ip)) ip else null
    }

    fun isInCgnat10064(ip: String): Boolean {
        val m = ipv4Regex.matchEntire(ip) ?: return false
        val octets = IntArray(4) { idx ->
            val v = m.groupValues[idx + 1].toIntOrNull() ?: return false
            if (v !in 0..255) return false
            v
        }
        // RFC 6598: 100.64.0.0/10 -> first octet 100, second octet 64..127.
        return octets[0] == 100 && octets[1] in 64..127
    }

    fun isValidIpv4(ip: String): Boolean {
        val m = ipv4Regex.matchEntire(ip) ?: return false
        return (1..4).all { idx ->
            val octet = m.groupValues[idx].toIntOrNull()
            octet != null && octet in 0..255
        }
    }

    fun isValidZone(zone: String): Boolean {
        val norm = zone.trim().lowercase()
        if (norm.isEmpty() || norm.length > 253 || !norm.contains('.')) {
            return false
        }
        val labels = norm.split('.')
        return labels.size >= 2 && labels.all { dnsLabelRegex.matches(it) }
    }

    /**
     * Always constructs https://home.<zone> from a strictly validated zone name
     * instead of launching an untrusted server-supplied portal URL.
     */
    fun homeUrlForZone(zone: String): String? {
        val norm = zone.trim().lowercase()
        if (!isValidZone(norm)) {
            return null
        }
        return "https://home.$norm"
    }

    fun encodeUpstreamDnsJson(servers: List<String>): String {
        val arr = JSONArray()
        for (s in servers) {
            val trimmed = s.trim()
            if (trimmed.isNotEmpty()) {
                arr.put(trimmed)
            }
        }
        return arr.toString()
    }

    private fun parsePenMeta(obj: JSONObject): PenMeta {
        val zone = obj.optString("zone", "").trim().lowercase()
        return PenMeta(
            zone = zone,
            loginServer = obj.optString("login_server", ""),
            portal = homeUrlForZone(zone).orEmpty(),
            dnsServer = obj.optString("dns_server", ""),
            hostname = obj.optString("hostname", ""),
            handle = obj.optString("handle", ""),
        )
    }

    private fun readStringList(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        val out = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) {
            val s = arr.optString(i, "").trim()
            if (s.isNotEmpty()) {
                out.add(s)
            }
        }
        return out
    }

    private fun <T> decodeObjectEnvelope(rawJson: String, decode: (JSONObject) -> T): ApiResult<T> {
        val env = parseEnvelope(rawJson) ?: return ApiResult.Err("invalid native JSON response")
        if (!env.optBoolean("ok", false)) {
            return ApiResult.Err(env.optString("error", "unknown error"))
        }
        val data = env.optJSONObject("data") ?: return ApiResult.Err("missing response data")
        return ApiResult.Ok(decode(data))
    }

    private fun parseEnvelope(rawJson: String): JSONObject? =
        try {
            JSONObject(rawJson)
        } catch (_: Exception) {
            null
        }
}
