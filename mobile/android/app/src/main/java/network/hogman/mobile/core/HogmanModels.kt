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
    private val ipv4Regex = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""")

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
            if (meta.zone.isNotBlank()) {
                out.add(meta)
            }
        }
        return ApiResult.Ok(out)
    }

    fun decodeTunnelStatus(rawJson: String): ApiResult<TunnelStatus> =
        decodeObjectEnvelope(rawJson) { obj ->
            TunnelStatus(
                state = obj.optString("state", "disconnected"),
                zone = obj.optString("zone", ""),
                portal = obj.optString("portal", ""),
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

    fun decodeTunnelReconfig(rawJson: String): TunnelReconfig? {
        val obj = parseEnvelope(rawJson) ?: return null
        val zone = obj.optString("zone", "").trim()
        val selfIpv4 = obj.optString("self_ipv4", "").trim()
        val dnsStubIp = obj.optString("dns_stub_ip", "").trim()
        val mtu = obj.optInt("mtu", 1280)
        if (zone.isEmpty() || !isValidIpv4(selfIpv4) || !isValidIpv4(dnsStubIp)) {
            return null
        }
        if (mtu < 1280 || mtu > 9000) {
            return null
        }
        return TunnelReconfig(
            zone = zone,
            selfIpv4 = selfIpv4,
            dnsIp = obj.optString("dns_ip", "").trim(),
            dnsStubIp = dnsStubIp,
            mtu = mtu,
            peerRoutes = readStringList(obj.optJSONArray("peer_routes")),
        )
    }

    /**
     * Strictly accepts exact IPv4 /32 host routes only (defense-in-depth against
     * broader prefixes like 0.0.0.0/0 or 100.64.0.0/10).
     */
    fun parseHost32Route(cidr: String): String? {
        val trimmed = cidr.trim()
        if (!trimmed.endsWith("/32")) {
            return null
        }
        val ip = trimmed.removeSuffix("/32")
        return if (isValidIpv4(ip)) ip else null
    }

    fun isValidIpv4(ip: String): Boolean {
        val m = ipv4Regex.matchEntire(ip) ?: return false
        return (1..4).all { idx ->
            val octet = m.groupValues[idx].toIntOrNull()
            octet != null && octet in 0..255
        }
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

    private fun parsePenMeta(obj: JSONObject): PenMeta =
        PenMeta(
            zone = obj.optString("zone", ""),
            loginServer = obj.optString("login_server", ""),
            portal = obj.optString("portal", ""),
            dnsServer = obj.optString("dns_server", ""),
            hostname = obj.optString("hostname", ""),
            handle = obj.optString("handle", ""),
        )

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
