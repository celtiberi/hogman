package network.hogman.mobile.ui

import android.Manifest
import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import network.hogman.mobile.core.ApiResult
import network.hogman.mobile.core.DeviceKeyStore
import network.hogman.mobile.core.HogmanNative
import network.hogman.mobile.core.ParsedLink
import network.hogman.mobile.core.PenMeta
import network.hogman.mobile.vpn.HogmanVpnService
import network.hogman.mobile.vpn.TunnelStateStore

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            HogmanTheme {
                HogmanAppScreen()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HogmanAppScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val tunnelSnap by TunnelStateStore.state.collectAsState()

    var pens by remember { mutableStateOf<List<PenMeta>>(emptyList()) }
    var busyMessage by remember { mutableStateOf<String?>(null) }
    var uiError by remember { mutableStateOf<String?>(null) }
    var pendingConnectZone by remember { mutableStateOf<String?>(null) }

    var showJoinDialog by remember { mutableStateOf(false) }
    var showQrScanner by remember { mutableStateOf(false) }
    var joinLinkText by remember { mutableStateOf("") }
    var leaveTarget by remember { mutableStateOf<PenMeta?>(null) }

    fun refreshPens() {
        scope.launch {
            val dataDir = DeviceKeyStore.dataDir(context)
            when (val res = withContext(Dispatchers.IO) { HogmanNative.listPens(dataDir) }) {
                is ApiResult.Ok -> pens = res.data
                is ApiResult.Err -> uiError = res.message
            }
        }
    }

    val notifPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* notification permission is optional; tunnel still runs */ }

    val vpnPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val zone = pendingConnectZone
        pendingConnectZone = null
        if (result.resultCode == Activity.RESULT_OK && zone != null) {
            HogmanVpnService.connect(context, zone)
        } else if (zone != null) {
            uiError = "VPN permission is required to connect to $zone."
        }
    }

    fun requestConnect(zone: String) {
        uiError = null
        TunnelStateStore.setError(null)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        val prep = VpnService.prepare(context)
        if (prep != null) {
            pendingConnectZone = zone
            vpnPermLauncher.launch(prep)
        } else {
            HogmanVpnService.connect(context, zone)
        }
    }

    LaunchedEffect(Unit) {
        TunnelStateStore.updateStatus(withContext(Dispatchers.IO) { HogmanNative.status() })
        refreshPens()
    }

    if (showQrScanner) {
        QrScannerScreen(
            onScanned = { text ->
                joinLinkText = text.trim()
                showQrScanner = false
                showJoinDialog = true
            },
            onCancel = {
                showQrScanner = false
                showJoinDialog = true
            },
        )
        return
    }

    Scaffold(
        containerColor = HogmanColors.Background,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "HOGMAN",
                            fontWeight = FontWeight.Black,
                            color = HogmanColors.Ink,
                        )
                        Spacer(Modifier.width(8.dp))
                        Surface(
                            color = HogmanColors.Surface,
                            shape = RoundedCornerShape(4.dp),
                            border = BorderStroke(1.dp, HogmanColors.Border),
                        ) {
                            Text(
                                text = "MOBILE",
                                style = MaterialTheme.typography.labelSmall,
                                color = HogmanColors.Accent,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = HogmanColors.Background,
                ),
                actions = {
                    TextButton(
                        onClick = {
                            joinLinkText = ""
                            showJoinDialog = true
                        },
                    ) {
                        Text("Join pen", color = HogmanColors.Accent)
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                ActiveTunnelCard(
                    status = tunnelSnap.status,
                    pens = pens,
                    onConnect = { requestConnect(it) },
                    onDisconnect = { HogmanVpnService.disconnect(context) },
                    onOpenHome = { openUrl(context, it) },
                )
            }

            if (tunnelSnap.privateDnsHostname != null) {
                item {
                    WarningBanner(
                        title = "Android Private DNS is pinned to ${tunnelSnap.privateDnsHostname}",
                        body = "Strict Private DNS bypasses Hogman's split resolver, so pen hostnames will not resolve. Switch Private DNS to Automatic or Off while using Hogman.",
                        actionLabel = "Open settings",
                        onAction = { openNetworkSettings(context) },
                    )
                }
            }

            if (tunnelSnap.lockdownActive) {
                item {
                    WarningBanner(
                        title = "\"Block connections without VPN\" is turned on",
                        body = "Hogman routes only pen addresses so your regular internet stays fast and private. Turn off \"Block connections without VPN\" in Android VPN settings to avoid blocking non-pen apps.",
                        actionLabel = "VPN settings",
                        onAction = { openVpnSettings(context) },
                    )
                }
            }

            val bannerErr = uiError ?: tunnelSnap.lastError
            if (!bannerErr.isNullOrBlank()) {
                item {
                    ErrorBanner(
                        message = bannerErr,
                        onDismiss = {
                            uiError = null
                            TunnelStateStore.setError(null)
                        },
                    )
                }
            }

            if (busyMessage != null) {
                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = HogmanColors.Accent,
                        )
                        Text(busyMessage!!, color = HogmanColors.InkMuted)
                    }
                }
            }

            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 6.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "Enrolled pens",
                        style = MaterialTheme.typography.titleMedium,
                        color = HogmanColors.Ink,
                    )
                    Button(
                        onClick = {
                            joinLinkText = ""
                            showJoinDialog = true
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = HogmanColors.AccentHot,
                            contentColor = MaterialTheme.colorScheme.onPrimary,
                        ),
                    ) {
                        Text("Join a pen", fontWeight = FontWeight.Bold)
                    }
                }
            }

            if (pens.isEmpty()) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = HogmanColors.Surface),
                        border = BorderStroke(1.dp, HogmanColors.Border),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(
                            modifier = Modifier.padding(18.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Text(
                                text = "No pens enrolled on this device yet.",
                                color = HogmanColors.Ink,
                                fontWeight = FontWeight.SemiBold,
                            )
                            Text(
                                text = "Scan a QR code from home.<pen> or paste an invite or device link to join.",
                                color = HogmanColors.InkMuted,
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    }
                }
            } else {
                items(pens, key = { it.zone }) { pen ->
                    val isThisPenActive = tunnelSnap.status.isActive && tunnelSnap.status.zone == pen.zone
                    val isThisPenConnected = tunnelSnap.status.state == "connected" && tunnelSnap.status.zone == pen.zone
                    PenRowCard(
                        pen = pen,
                        isActive = isThisPenActive,
                        isConnected = isThisPenConnected,
                        onConnect = { requestConnect(pen.zone) },
                        onDisconnect = { HogmanVpnService.disconnect(context) },
                        onOpenHome = { openUrl(context, pen.portal.ifBlank { "https://home.${pen.zone}" }) },
                        onLeave = { leaveTarget = pen },
                    )
                }
            }

            item { Spacer(Modifier.height(24.dp)) }
        }
    }

    if (showJoinDialog) {
        JoinPenDialog(
            initialLink = joinLinkText,
            onOpenScanner = {
                showJoinDialog = false
                showQrScanner = true
            },
            onDismiss = { showJoinDialog = false },
            onJoined = { meta ->
                showJoinDialog = false
                joinLinkText = ""
                refreshPens()
                requestConnect(meta.zone)
            },
        )
    }

    leaveTarget?.let { target ->
        LeavePenDialog(
            pen = target,
            isConnectedToPen = tunnelSnap.status.state == "connected" && tunnelSnap.status.zone == target.zone,
            onDismiss = { leaveTarget = null },
            onComplete = { zone ->
                leaveTarget = null
                if (tunnelSnap.status.zone == zone) {
                    HogmanVpnService.disconnect(context)
                }
                busyMessage = null
                refreshPens()
            },
        )
    }
}

@Composable
private fun ActiveTunnelCard(
    status: network.hogman.mobile.core.TunnelStatus,
    pens: List<PenMeta>,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
    onOpenHome: (String) -> Unit,
) {
    val dotColor = when (status.state) {
        "connected" -> HogmanColors.Ok
        "connecting" -> HogmanColors.Accent
        "removed", "error" -> HogmanColors.Danger
        else -> HogmanColors.InkMuted
    }
    val statusLabel = when (status.state) {
        "connected" -> "Connected"
        "connecting" -> "Connecting…"
        "removed" -> "Removed from pen"
        "error" -> "Error"
        else -> "Disconnected"
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = HogmanColors.Surface),
        border = BorderStroke(
            width = if (status.state == "connected") 1.5.dp else 1.dp,
            color = if (status.state == "connected") HogmanColors.Ok else HogmanColors.Border,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(dotColor),
                )
                Text(
                    text = statusLabel,
                    color = dotColor,
                    fontWeight = FontWeight.Bold,
                )
            }

            if (status.zone.isNotBlank()) {
                Text(
                    text = status.zone,
                    style = MaterialTheme.typography.titleMedium,
                    color = HogmanColors.Ink,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                )
            } else {
                Text(
                    text = if (pens.isEmpty()) "Ready to join a pen" else "Select a pen below to connect",
                    style = MaterialTheme.typography.titleMedium,
                    color = HogmanColors.Ink,
                )
            }

            if (status.state == "connected" && status.selfIpv4.isNotBlank()) {
                Text(
                    text = "Device ${status.selfIpv4} · ${status.peerRoutes.size} split /32 route(s) · Regular internet untouched",
                    style = MaterialTheme.typography.bodySmall,
                    color = HogmanColors.InkMuted,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                if (status.isActive) {
                    OutlinedButton(
                        onClick = onDisconnect,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Disconnect")
                    }
                    if (status.state == "connected") {
                        val portalUrl = status.portal.ifBlank { "https://home.${status.zone}" }
                        Button(
                            onClick = { onOpenHome(portalUrl) },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = HogmanColors.Accent,
                                contentColor = MaterialTheme.colorScheme.onSecondary,
                            ),
                        ) {
                            Text("Open Home", fontWeight = FontWeight.Bold)
                        }
                    }
                } else if (pens.size == 1) {
                    Button(
                        onClick = { onConnect(pens.first().zone) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = HogmanColors.AccentHot,
                            contentColor = MaterialTheme.colorScheme.onPrimary,
                        ),
                    ) {
                        Text("Connect to ${pens.first().zone}", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}

@Composable
private fun PenRowCard(
    pen: PenMeta,
    isActive: Boolean,
    isConnected: Boolean,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onOpenHome: () -> Unit,
    onLeave: () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = HogmanColors.SurfaceWell),
        border = BorderStroke(1.dp, if (isConnected) HogmanColors.Ok else HogmanColors.Border),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = pen.zone,
                        style = MaterialTheme.typography.bodyMedium,
                        color = HogmanColors.Ink,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                    )
                    val metaLine = buildList {
                        if (pen.handle.isNotBlank()) add("@${pen.handle}")
                        if (pen.hostname.isNotBlank()) add(pen.hostname)
                    }.joinToString(" · ")
                    if (metaLine.isNotBlank()) {
                        Text(
                            text = metaLine,
                            color = HogmanColors.InkMuted,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                TextButton(onClick = onLeave) {
                    Text("Leave", color = HogmanColors.Danger)
                }
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (isActive) {
                    OutlinedButton(onClick = onDisconnect) {
                        Text("Disconnect")
                    }
                } else {
                    Button(
                        onClick = onConnect,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = HogmanColors.AccentHot,
                            contentColor = MaterialTheme.colorScheme.onPrimary,
                        ),
                    ) {
                        Text("Connect")
                    }
                }
                if (isConnected) {
                    OutlinedButton(onClick = onOpenHome) {
                        Text("Open Home", color = HogmanColors.Accent)
                    }
                }
            }
        }
    }
}

@Composable
private fun WarningBanner(
    title: String,
    body: String,
    actionLabel: String,
    onAction: () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = HogmanColors.WarnBg),
        border = BorderStroke(1.dp, HogmanColors.Accent),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(title, color = HogmanColors.Accent, fontWeight = FontWeight.Bold)
            Text(body, color = HogmanColors.Ink, style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onAction) {
                Text(actionLabel, color = HogmanColors.Accent)
            }
        }
    }
}

@Composable
private fun ErrorBanner(
    message: String,
    onDismiss: () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = HogmanColors.DangerBg),
        border = BorderStroke(1.dp, HogmanColors.Danger),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = message,
                color = HogmanColors.Ink,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onDismiss) {
                Text("Dismiss", color = HogmanColors.Danger)
            }
        }
    }
}

@Composable
private fun JoinPenDialog(
    initialLink: String,
    onOpenScanner: () -> Unit,
    onDismiss: () -> Unit,
    onJoined: (PenMeta) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var rawLink by remember(initialLink) { mutableStateOf(initialLink) }
    var pastedFromClipboard by remember { mutableStateOf(false) }
    var parsed by remember { mutableStateOf<ParsedLink?>(null) }
    var parseErr by remember { mutableStateOf<String?>(null) }
    var handle by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf(defaultDeviceName()) }
    var submitErr by remember { mutableStateOf<String?>(null) }
    var submitting by remember { mutableStateOf(false) }

    LaunchedEffect(rawLink) {
        submitErr = null
        val trimmed = rawLink.trim()
        if (trimmed.isEmpty()) {
            parsed = null
            parseErr = null
            return@LaunchedEffect
        }
        when (val res = withContext(Dispatchers.IO) { HogmanNative.parseLink(trimmed) }) {
            is ApiResult.Ok -> {
                parsed = res.data
                parseErr = null
            }

            is ApiResult.Err -> {
                parsed = null
                parseErr = res.message
            }
        }
    }

    AlertDialog(
        onDismissRequest = { if (!submitting) onDismiss() },
        containerColor = HogmanColors.Surface,
        title = { Text("Join a pen", color = HogmanColors.Ink) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(
                        onClick = onOpenScanner,
                        enabled = !submitting,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Scan QR")
                    }
                    OutlinedButton(
                        onClick = {
                            val clip = readClipboardExplicit(context)
                            if (clip.isNullOrBlank()) {
                                submitErr = "Clipboard is empty."
                            } else {
                                rawLink = clip.trim()
                                pastedFromClipboard = true
                            }
                        },
                        enabled = !submitting,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Paste link")
                    }
                }

                OutlinedTextField(
                    value = rawLink,
                    onValueChange = { rawLink = it },
                    label = { Text("Join or invite link") },
                    singleLine = true,
                    enabled = !submitting,
                    modifier = Modifier.fillMaxWidth(),
                )

                parsed?.let { p ->
                    Text(
                        text = if (p.kind == "invite") {
                            "Invite link for ${p.host}"
                        } else {
                            "One-time device link for ${p.host}"
                        },
                        color = HogmanColors.Ok,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                parseErr?.let { err ->
                    Text(err, color = HogmanColors.Danger, style = MaterialTheme.typography.bodySmall)
                }

                if (parsed?.kind == "invite") {
                    OutlinedTextField(
                        value = handle,
                        onValueChange = { handle = it.lowercase() },
                        label = { Text("Choose your handle (e.g. alice)") },
                        singleLine = true,
                        enabled = !submitting,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                OutlinedTextField(
                    value = deviceName,
                    onValueChange = { deviceName = it },
                    label = { Text("Device name") },
                    singleLine = true,
                    enabled = !submitting,
                    modifier = Modifier.fillMaxWidth(),
                )

                submitErr?.let { err ->
                    Text(err, color = HogmanColors.Danger, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            Button(
                enabled = !submitting && parsed != null && (parsed?.kind != "invite" || handle.isNotBlank()),
                onClick = {
                    submitting = true
                    submitErr = null
                    val linkCopy = rawLink.trim()
                    val handleCopy = handle.trim()
                    val devCopy = deviceName.trim()
                    scope.launch {
                        val res = withContext(Dispatchers.IO) {
                            val dataDir = DeviceKeyStore.dataDir(context)
                            DeviceKeyStore.withStateKey(context) { dek ->
                                HogmanNative.join(
                                    dataDir = dataDir,
                                    stateKey = dek,
                                    rawLink = linkCopy,
                                    handle = handleCopy,
                                    deviceName = devCopy,
                                )
                            }
                        }
                        submitting = false
                        when (res) {
                            is ApiResult.Ok -> {
                                if (pastedFromClipboard) {
                                    clearClipboard(context)
                                }
                                onJoined(res.data)
                            }
                            is ApiResult.Err -> submitErr = res.message
                        }
                    }
                },
            ) {
                Text(if (submitting) "Joining…" else "Join")
            }
        },
        dismissButton = {
            TextButton(enabled = !submitting, onClick = onDismiss) {
                Text("Cancel")
            }
        },
    )
}

@Composable
private fun LeavePenDialog(
    pen: PenMeta,
    isConnectedToPen: Boolean,
    onDismiss: () -> Unit,
    onComplete: (String) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var needForceConfirm by remember { mutableStateOf(!isConnectedToPen) }
    var typedZone by remember { mutableStateOf("") }
    var errMsg by remember { mutableStateOf<String?>(null) }
    var leaving by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { if (!leaving) onDismiss() },
        containerColor = HogmanColors.Surface,
        title = { Text("Leave ${pen.zone}?", color = HogmanColors.Ink) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = if (needForceConfirm) {
                        "Force-leaving deletes local keys on this device even if the pen cannot be reached (or if this is your last owner device). Type ${pen.zone} to confirm."
                    } else {
                        "This removes this device from ${pen.zone} and deletes its local keys."
                    },
                    color = HogmanColors.InkMuted,
                    style = MaterialTheme.typography.bodySmall,
                )

                if (needForceConfirm) {
                    OutlinedTextField(
                        value = typedZone,
                        onValueChange = { typedZone = it },
                        label = { Text("Type ${pen.zone}") },
                        singleLine = true,
                        enabled = !leaving,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                errMsg?.let {
                    Text(it, color = HogmanColors.Danger, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            val canConfirm = !leaving && (!needForceConfirm || typedZone.trim() == pen.zone)
            Button(
                enabled = canConfirm,
                colors = ButtonDefaults.buttonColors(
                    containerColor = HogmanColors.Danger,
                    contentColor = MaterialTheme.colorScheme.onError,
                ),
                onClick = {
                    leaving = true
                    errMsg = null
                    val force = needForceConfirm
                    scope.launch {
                        val res = withContext(Dispatchers.IO) {
                            val dataDir = DeviceKeyStore.dataDir(context)
                            DeviceKeyStore.withStateKey(context) { dek ->
                                HogmanNative.leave(dataDir, dek, pen.zone, force)
                            }
                        }
                        leaving = false
                        when (res) {
                            is ApiResult.Ok -> onComplete(pen.zone)
                            is ApiResult.Err -> {
                                errMsg = res.message
                                // Surface typed-confirmation force-leave if sole-owner or offline error.
                                needForceConfirm = true
                            }
                        }
                    }
                },
            ) {
                Text(if (leaving) "Leaving…" else if (needForceConfirm) "Force leave" else "Leave")
            }
        },
        dismissButton = {
            TextButton(enabled = !leaving, onClick = onDismiss) {
                Text("Cancel")
            }
        },
    )
}

private fun defaultDeviceName(): String {
    val raw = Build.MODEL?.trim().orEmpty()
    val clean = raw.lowercase().replace(Regex("[^a-z0-9-]+"), "-").trim('-')
    return clean.ifBlank { "android" }.take(32)
}

private fun readClipboardExplicit(context: Context): String? {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return null
    val clip = cm.primaryClip ?: return null
    if (clip.itemCount <= 0) return null
    return clip.getItemAt(0).coerceToText(context)?.toString()
}

private fun clearClipboard(context: Context) {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return
    try {
        cm.clearPrimaryClip()
    } catch (_: Throwable) {
    }
}

private fun openUrl(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
    context.startActivity(intent)
}

private fun openNetworkSettings(context: Context) {
    val intent = Intent(Settings.ACTION_WIRELESS_SETTINGS).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    try {
        context.startActivity(intent)
    } catch (_: Throwable) {
        context.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}

private fun openVpnSettings(context: Context) {
    val intent = Intent(Settings.ACTION_VPN_SETTINGS).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    try {
        context.startActivity(intent)
    } catch (_: Throwable) {
        context.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}
