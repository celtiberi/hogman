package network.hogman.mobile.core

interface TunnelCallbackTarget {
    fun protectFd(fd: Int): Int
    fun onTunnelReconfig(reconfigUtf8: ByteArray): Int
}

object HogmanNative {
    init {
        System.loadLibrary("hogman")
        System.loadLibrary("hogman_jni")
    }

    @JvmStatic
    private external fun nativeParseLink(rawLink: String): ByteArray?

    @JvmStatic
    private external fun nativeJoin(
        dataDir: String,
        stateKey: ByteArray,
        rawLink: String,
        handle: String,
        deviceName: String,
        controlCAPEM: String,
    ): ByteArray?

    @JvmStatic
    private external fun nativeListPens(dataDir: String): ByteArray?

    @JvmStatic
    private external fun nativeStartTunnel(
        dataDir: String,
        stateKey: ByteArray,
        zone: String,
        mtu: Int,
        upstreamDNSJSON: String,
        callbackTarget: TunnelCallbackTarget,
    ): ByteArray?

    @JvmStatic
    private external fun nativeUpdateNetwork(
        upstreamDNSJSON: String,
        linkChanged: Boolean,
    ): ByteArray?

    @JvmStatic
    private external fun nativeStatus(): ByteArray?

    @JvmStatic
    private external fun nativeStopTunnel(): ByteArray?

    @JvmStatic
    private external fun nativeLeave(
        dataDir: String,
        stateKey: ByteArray,
        zone: String,
        force: Boolean,
    ): ByteArray?

    private fun decodeUtf8(raw: ByteArray?): String =
        if (raw == null) {
            """{"ok":false,"error":"null native response"}"""
        } else {
            String(raw, Charsets.UTF_8)
        }

    fun parseLink(rawLink: String): ApiResult<ParsedLink> =
        HogmanModels.decodeParsedLink(decodeUtf8(nativeParseLink(rawLink)))

    fun join(
        dataDir: String,
        stateKey: ByteArray,
        rawLink: String,
        handle: String,
        deviceName: String,
        controlCAPEM: String = "",
    ): ApiResult<PenMeta> =
        HogmanModels.decodePenMeta(
            decodeUtf8(nativeJoin(dataDir, stateKey, rawLink, handle, deviceName, controlCAPEM)),
        )

    fun listPens(dataDir: String): ApiResult<List<PenMeta>> =
        HogmanModels.decodePenList(decodeUtf8(nativeListPens(dataDir)))

    fun startTunnel(
        dataDir: String,
        stateKey: ByteArray,
        zone: String,
        mtu: Int,
        upstreamDNSJSON: String,
        callbackTarget: TunnelCallbackTarget,
    ): ApiResult<TunnelStatus> =
        HogmanModels.decodeTunnelStatus(
            decodeUtf8(nativeStartTunnel(dataDir, stateKey, zone, mtu, upstreamDNSJSON, callbackTarget)),
        )

    fun updateNetwork(upstreamDNSJSON: String, linkChanged: Boolean): ApiResult<Unit> =
        HogmanModels.decodeUnit(decodeUtf8(nativeUpdateNetwork(upstreamDNSJSON, linkChanged)))

    fun status(): TunnelStatus =
        when (val res = HogmanModels.decodeTunnelStatus(decodeUtf8(nativeStatus()))) {
            is ApiResult.Ok -> res.data
            is ApiResult.Err -> TunnelStatus(state = "error", error = res.message)
        }

    fun stopTunnel(): TunnelStatus =
        when (val res = HogmanModels.decodeTunnelStatus(decodeUtf8(nativeStopTunnel()))) {
            is ApiResult.Ok -> res.data
            is ApiResult.Err -> TunnelStatus.Disconnected
        }

    fun leave(
        dataDir: String,
        stateKey: ByteArray,
        zone: String,
        force: Boolean,
    ): ApiResult<Unit> =
        HogmanModels.decodeUnit(decodeUtf8(nativeLeave(dataDir, stateKey, zone, force)))
}
