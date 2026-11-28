package network.hogman.mobile.core

interface TunnelCallbackTarget {
    fun protectFd(fd: Int): Int
    fun onTunnelReconfig(reconfigJson: String): Int
}

object HogmanNative {
    init {
        System.loadLibrary("hogman")
        System.loadLibrary("hogman_jni")
    }

    @JvmStatic
    private external fun nativeParseLink(rawLink: String): String

    @JvmStatic
    private external fun nativeJoin(
        dataDir: String,
        stateKey: ByteArray,
        rawLink: String,
        handle: String,
        deviceName: String,
        controlCAPEM: String,
    ): String

    @JvmStatic
    private external fun nativeListPens(dataDir: String): String

    @JvmStatic
    private external fun nativeStartTunnel(
        dataDir: String,
        stateKey: ByteArray,
        zone: String,
        mtu: Int,
        upstreamDNSJSON: String,
        callbackTarget: TunnelCallbackTarget,
    ): String

    @JvmStatic
    private external fun nativeUpdateNetwork(
        upstreamDNSJSON: String,
        linkChanged: Boolean,
    ): String

    @JvmStatic
    private external fun nativeStatus(): String

    @JvmStatic
    private external fun nativeStopTunnel(): String

    @JvmStatic
    private external fun nativeLeave(
        dataDir: String,
        stateKey: ByteArray,
        zone: String,
        force: Boolean,
    ): String

    fun parseLink(rawLink: String): ApiResult<ParsedLink> =
        HogmanModels.decodeParsedLink(nativeParseLink(rawLink))

    fun join(
        dataDir: String,
        stateKey: ByteArray,
        rawLink: String,
        handle: String,
        deviceName: String,
        controlCAPEM: String = "",
    ): ApiResult<PenMeta> =
        HogmanModels.decodePenMeta(
            nativeJoin(dataDir, stateKey, rawLink, handle, deviceName, controlCAPEM),
        )

    fun listPens(dataDir: String): ApiResult<List<PenMeta>> =
        HogmanModels.decodePenList(nativeListPens(dataDir))

    fun startTunnel(
        dataDir: String,
        stateKey: ByteArray,
        zone: String,
        mtu: Int,
        upstreamDNSJSON: String,
        callbackTarget: TunnelCallbackTarget,
    ): ApiResult<TunnelStatus> =
        HogmanModels.decodeTunnelStatus(
            nativeStartTunnel(dataDir, stateKey, zone, mtu, upstreamDNSJSON, callbackTarget),
        )

    fun updateNetwork(upstreamDNSJSON: String, linkChanged: Boolean): ApiResult<Unit> =
        HogmanModels.decodeUnit(nativeUpdateNetwork(upstreamDNSJSON, linkChanged))

    fun status(): TunnelStatus =
        when (val res = HogmanModels.decodeTunnelStatus(nativeStatus())) {
            is ApiResult.Ok -> res.data
            is ApiResult.Err -> TunnelStatus(state = "error", error = res.message)
        }

    fun stopTunnel(): TunnelStatus =
        when (val res = HogmanModels.decodeTunnelStatus(nativeStopTunnel())) {
            is ApiResult.Ok -> res.data
            is ApiResult.Err -> TunnelStatus.Disconnected
        }

    fun leave(
        dataDir: String,
        stateKey: ByteArray,
        zone: String,
        force: Boolean,
    ): ApiResult<Unit> =
        HogmanModels.decodeUnit(nativeLeave(dataDir, stateKey, zone, force))
}
