package network.hogman.mobile.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import network.hogman.mobile.R
import network.hogman.mobile.core.ApiResult
import network.hogman.mobile.core.DeviceKeyStore
import network.hogman.mobile.core.HogmanModels
import network.hogman.mobile.core.HogmanNative
import network.hogman.mobile.core.TunnelCallbackTarget
import network.hogman.mobile.core.TunnelStatus
import network.hogman.mobile.ui.MainActivity

/**
 * Split-tunnel Android VpnService backed by libhogman.
 *
 * Routes ONLY exact /32 active pen peer addresses plus 100.100.100.100/32
 * through the TUN interface; all non-pen internet traffic stays on the user's
 * normal network. Non-pen DNS queries received by the split-DNS stub are
 * forwarded directly to the underlying physical network's DNS servers via
 * VpnService.protect(fd) with zero logging or caching.
 */
class HogmanVpnService : VpnService(), TunnelCallbackTarget {

    private val worker = Executors.newSingleThreadExecutor { r ->
        Thread(r, "hogman-vpn-worker").apply { isDaemon = true }
    }
    private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "hogman-vpn-poll").apply { isDaemon = true }
    }

    private val underlyingLinks = ConcurrentHashMap<Network, LinkProperties>()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var pollFuture: ScheduledFuture<*>? = null

    @Volatile
    private var activeZone: String? = null

    @Volatile
    private var lastNotifText: String = ""

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val zone = intent.getStringExtra(EXTRA_ZONE)?.trim().orEmpty()
                if (zone.isEmpty()) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                startForegroundWithText("Connecting to $zone…")
                worker.execute { connectInternal(zone) }
            }

            ACTION_DISCONNECT -> {
                worker.execute { disconnectInternal(clearError = true) }
            }

            else -> {
                if (activeZone == null) {
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        worker.execute {
            TunnelStateStore.setError("VPN permission was revoked by Android.")
            disconnectInternal(clearError = false)
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        unregisterNetworkMonitor()
        stopStatusPoller()
        try {
            HogmanNative.stopTunnel()
        } catch (_: Throwable) {
        }
        TunnelStateStore.updateStatus(TunnelStatus.Disconnected)
        worker.shutdownNow()
        scheduler.shutdownNow()
        super.onDestroy()
    }

    // Invoked by libhogman via hogman_jni.c from Go goroutines.
    override fun protectFd(fd: Int): Int = if (protect(fd)) 0 else -1

    // Invoked by libhogman via hogman_jni.c whenever self IP or active /32 peer routes change.
    override fun onTunnelReconfig(reconfigJson: String): Int {
        val cfg = HogmanModels.decodeTunnelReconfig(reconfigJson) ?: return -2
        val routes = ArrayList<String>(cfg.peerRoutes.size)
        for (cidr in cfg.peerRoutes) {
            val hostIp = HogmanModels.parseHost32Route(cidr) ?: return -2
            routes.add(hostIp)
        }
        if (routes.isEmpty()) {
            return -2
        }

        return try {
            val builder = Builder()
                .setSession("Hogman · ${cfg.zone}")
                .setMtu(cfg.mtu)
                .addAddress(cfg.selfIpv4, 32)
                .addDnsServer(cfg.dnsStubIp)

            for (ip in routes) {
                builder.addRoute(ip, 32)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            val pfd = builder.establish() ?: return -2
            // Transfer ownership of the TUN file descriptor to Go's SwappableTUN.
            pfd.detachFd()
        } catch (_: Throwable) {
            -2
        }
    }

    private fun connectInternal(zone: String) {
        activeZone = zone
        registerNetworkMonitor()
        val initialDns = snapshotUnderlyingNetwork()
        TunnelStateStore.updateStatus(TunnelStatus(state = "connecting", zone = zone))

        val dataDir = DeviceKeyStore.dataDir(applicationContext)
        val result = try {
            DeviceKeyStore.withStateKey(applicationContext) { dek ->
                HogmanNative.startTunnel(
                    dataDir = dataDir,
                    stateKey = dek,
                    zone = zone,
                    mtu = DEFAULT_MTU,
                    upstreamDNSJSON = initialDns,
                    callbackTarget = this,
                )
            }
        } catch (t: Throwable) {
            ApiResult.Err(t.message ?: "failed to open device encryption key")
        }

        when (result) {
            is ApiResult.Ok -> {
                TunnelStateStore.updateStatus(result.data)
                startStatusPoller()
            }

            is ApiResult.Err -> {
                TunnelStateStore.setError(result.message)
                disconnectInternal(clearError = false)
            }
        }
    }

    private fun disconnectInternal(clearError: Boolean) {
        activeZone = null
        stopStatusPoller()
        unregisterNetworkMonitor()
        val st = try {
            HogmanNative.stopTunnel()
        } catch (_: Throwable) {
            TunnelStatus.Disconnected
        }
        TunnelStateStore.updateStatus(st)
        if (clearError) {
            TunnelStateStore.setError(null)
        }
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startStatusPoller() {
        stopStatusPoller()
        pollFuture = scheduler.scheduleWithFixedDelay(
            {
                val st = HogmanNative.status()
                TunnelStateStore.updateStatus(st)
                val lockdown = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isLockdownEnabled
                val currentPrivateDns = TunnelStateStore.state.value.privateDnsHostname
                TunnelStateStore.updateNetworkFlags(currentPrivateDns, lockdown)

                when (st.state) {
                    "connected" -> {
                        val label = "Connected to ${st.zone}"
                        if (label != lastNotifText) {
                            startForegroundWithText(label)
                        }
                    }

                    "connecting" -> {
                        val label = "Connecting to ${st.zone.ifBlank { activeZone.orEmpty() }}…"
                        if (label != lastNotifText) {
                            startForegroundWithText(label)
                        }
                    }

                    "removed", "error" -> {
                        // Fail-safe teardown: never leave Android pointed at a dead VPN DNS stub.
                        worker.execute {
                            val errMsg = st.error.ifBlank {
                                if (st.state == "removed") {
                                    "This device was removed from the pen."
                                } else {
                                    "Tunnel stopped unexpectedly."
                                }
                            }
                            TunnelStateStore.setError(errMsg)
                            disconnectInternal(clearError = false)
                        }
                    }

                    "disconnected" -> {
                        if (activeZone != null) {
                            worker.execute { disconnectInternal(clearError = false) }
                        }
                    }
                }
            },
            500L,
            1000L,
            TimeUnit.MILLISECONDS,
        )
    }

    private fun stopStatusPoller() {
        pollFuture?.cancel(false)
        pollFuture = null
    }

    private fun registerNetworkMonitor() {
        unregisterNetworkMonitor()
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        seedUnderlyingLinks(cm)

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                cm.getLinkProperties(network)?.let { underlyingLinks[network] = it }
                pushUnderlyingNetworkUpdate(linkChanged = true)
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                underlyingLinks[network] = linkProperties
                pushUnderlyingNetworkUpdate(linkChanged = false)
            }

            override fun onLost(network: Network) {
                underlyingLinks.remove(network)
                pushUnderlyingNetworkUpdate(linkChanged = true)
            }
        }
        networkCallback = cb
        try {
            cm.registerNetworkCallback(request, cb)
        } catch (_: Throwable) {
        }
    }

    private fun unregisterNetworkMonitor() {
        val cb = networkCallback ?: return
        networkCallback = null
        val cm = getSystemService(ConnectivityManager::class.java)
        try {
            cm?.unregisterNetworkCallback(cb)
        } catch (_: Throwable) {
        }
        underlyingLinks.clear()
    }

    @Suppress("DEPRECATION")
    private fun seedUnderlyingLinks(cm: ConnectivityManager) {
        underlyingLinks.clear()
        for (net in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(net) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
            val lp = cm.getLinkProperties(net) ?: continue
            underlyingLinks[net] = lp
        }
    }

    private fun snapshotUnderlyingNetwork(): String {
        val cm = getSystemService(ConnectivityManager::class.java)
        val selected = selectBestUnderlyingLink(cm)
        val privateDnsHost = if (selected != null && selected.isPrivateDnsActive) {
            selected.privateDnsServerName?.takeIf { it.isNotBlank() }
        } else {
            null
        }
        val lockdown = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isLockdownEnabled
        TunnelStateStore.updateNetworkFlags(privateDnsHost, lockdown)

        val servers = extractUpstreamDns(selected)
        return HogmanModels.encodeUpstreamDnsJson(servers)
    }

    private fun pushUnderlyingNetworkUpdate(linkChanged: Boolean) {
        val dnsJson = snapshotUnderlyingNetwork()
        if (activeZone != null) {
            try {
                HogmanNative.updateNetwork(dnsJson, linkChanged)
            } catch (_: Throwable) {
            }
        }
    }

    private fun selectBestUnderlyingLink(cm: ConnectivityManager?): LinkProperties? {
        if (underlyingLinks.isEmpty()) return null
        var best: LinkProperties? = null
        var bestScore = -1
        for ((net, lp) in underlyingLinks.entries) {
            val caps = cm?.getNetworkCapabilities(net)
            var score = 0
            if (caps != null) {
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) score += 10
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) score += 6
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) score += 5
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) score += 2
            }
            if (lp.dnsServers.isNotEmpty()) score += 1
            if (score > bestScore) {
                bestScore = score
                best = lp
            }
        }
        return best
    }

    private fun extractUpstreamDns(lp: LinkProperties?): List<String> {
        if (lp == null) return emptyList()
        val v4 = ArrayList<String>()
        val v6 = ArrayList<String>()
        for (addr: InetAddress in lp.dnsServers) {
            if (addr.isLoopbackAddress || addr.isAnyLocalAddress || addr.isLinkLocalAddress) {
                continue
            }
            val host = addr.hostAddress?.substringBefore('%') ?: continue
            if (host == SPLIT_DNS_STUB_IP) continue
            if (addr is Inet4Address) {
                v4.add(host)
            } else {
                v6.add(host)
            }
        }
        return v4 + v6
    }

    private fun ensureNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.vpn_channel_description)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    private fun startForegroundWithText(text: String) {
        lastNotifText = text
        val notif = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceCompat.startForeground(
                this,
                NOTIF_ID,
                notif,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    private fun buildNotification(text: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, HogmanVpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .addAction(0, "Disconnect", stopIntent)
            .build()
    }

    companion object {
        const val ACTION_CONNECT = "network.hogman.mobile.action.CONNECT"
        const val ACTION_DISCONNECT = "network.hogman.mobile.action.DISCONNECT"
        const val EXTRA_ZONE = "zone"

        private const val CHANNEL_ID = "hogman_vpn"
        private const val NOTIF_ID = 1001
        private const val DEFAULT_MTU = 1280
        private const val SPLIT_DNS_STUB_IP = "100.100.100.100"

        fun connect(context: Context, zone: String) {
            val intent = Intent(context, HogmanVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_ZONE, zone)
            }
            context.startForegroundService(intent)
        }

        fun disconnect(context: Context) {
            val intent = Intent(context, HogmanVpnService::class.java).apply {
                action = ACTION_DISCONNECT
            }
            context.startService(intent)
        }
    }
}
