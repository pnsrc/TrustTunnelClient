package me.pnsrc.firetunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import com.adguard.trusttunnel.VpnClient
import com.adguard.trusttunnel.VpnClientListener
import com.adguard.trusttunnel.VpnState
import me.pnsrc.firetunnel.data.AppRoutingManager
import me.pnsrc.firetunnel.data.ConfigFields
import java.util.concurrent.atomic.AtomicLong

/**
 * FireTunnel VPN foreground service.
 *
 * Threading model
 * ───────────────
 * [startForeground] is called immediately on the main thread within 5 s of
 * [startForegroundService].  All blocking work (TUN setup, native client start)
 * runs on a dedicated "vpn-connect" background thread.
 *
 * State cache
 * ───────────
 * [lastKnownState] is a process-wide in-memory cache so that [HomeFragment]
 * can restore the correct UI state when re-created after a tab switch.
 */
class FireTunnelVpnService : VpnService() {

    companion object {
        private const val TAG = "FireTunnelVpn"

        const val ACTION_CONNECT    = "me.pnsrc.firetunnel.CONNECT"
        const val ACTION_DISCONNECT = "me.pnsrc.firetunnel.DISCONNECT"
        const val EXTRA_CONFIG_TOML = "config_toml"
        const val EXTRA_CONFIG_ID   = "config_id"

        const val BROADCAST_STATE    = "me.pnsrc.firetunnel.VPN_STATE"
        const val EXTRA_STATE        = "state"
        const val STATE_CONNECTED    = "CONNECTED"
        const val STATE_CONNECTING   = "CONNECTING"
        const val STATE_DISCONNECTED = "DISCONNECTED"
        const val STATE_ERROR        = "ERROR"
        const val EXTRA_ERROR_MSG    = "error_msg"
        const val EXTRA_CONNECTED_AT = "connected_at"

        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID      = "firetunnel_vpn"

        /** In-process VPN state cache — read by HomeFragment on resume. */
        @Volatile var lastKnownState: String = STATE_DISCONNECTED

        /** Id of the config the VPN was started with; `null` when stopped. */
        @Volatile var activeConfigId: String? = null

        // ── Session statistics (read by HomeFragment once a second) ─────────────
        @Volatile private var sessionStartedAt = 0L
        @Volatile private var rxBase = 0L
        @Volatile private var txBase = 0L
        private val tunnelConnections = AtomicLong()
        private val bypassConnections = AtomicLong()
        private val ACTION_REGEX = Regex(""""action"\s*:\s*"(\w+)"""")

        /**
         * Return statistics of the running session, or `null` when not connected.
         * All tunnel I/O happens inside this process, so the app's own UID traffic is
         * the VPN traffic; byte counts are `null` if the kernel does not report them.
         */
        fun sessionStats(): SessionStats? {
            val startedAt = sessionStartedAt
            if (startedAt == 0L) return null
            val uid = Process.myUid()
            val rx = TrafficStats.getUidRxBytes(uid)
            val tx = TrafficStats.getUidTxBytes(uid)
            val supported = rx != TrafficStats.UNSUPPORTED.toLong() && tx != TrafficStats.UNSUPPORTED.toLong()
            return SessionStats(
                connectedAt = startedAt,
                rxBytes = if (supported) (rx - rxBase).coerceAtLeast(0) else null,
                txBytes = if (supported) (tx - txBase).coerceAtLeast(0) else null,
                tunnelConnections = tunnelConnections.get(),
                bypassConnections = bypassConnections.get()
            )
        }

        private fun startSession() {
            if (sessionStartedAt != 0L) return // reconnect within the same session
            val uid = Process.myUid()
            rxBase = TrafficStats.getUidRxBytes(uid)
            txBase = TrafficStats.getUidTxBytes(uid)
            tunnelConnections.set(0)
            bypassConnections.set(0)
            sessionStartedAt = System.currentTimeMillis()
        }

        private fun endSession() {
            sessionStartedAt = 0L
        }

        private fun countConnection(infoJson: String) {
            when (ACTION_REGEX.find(infoJson)?.groupValues?.get(1)) {
                "tunnel" -> tunnelConnections.incrementAndGet()
                "bypass" -> bypassConnections.incrementAndGet()
            }
        }
    }

    @Volatile private var vpnClient: VpnClient? = null
    @Volatile private var fallbackTun: ParcelFileDescriptor? = null
    @Volatile private var connectThread: Thread? = null

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        VpnClient.tryLoadLibrary()
        connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val toml = intent.getStringExtra(EXTRA_CONFIG_TOML) ?: ""
                activeConfigId = intent.getStringExtra(EXTRA_CONFIG_ID)
                broadcastState(STATE_CONNECTING)
                startForegroundCompat(buildNotification(STATE_CONNECTING))
                cancelConnectThread()
                connectThread = Thread({ connectInBackground(toml, startId) }, "vpn-connect")
                    .also { it.start() }
            }
            ACTION_DISCONNECT -> stopVpn(startId)
            else -> stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked")
        stopVpn(null)
    }

    override fun onDestroy() {
        super.onDestroy()
        cancelConnectThread()
        unregisterNetworkCallback()
        teardownVpnClient()
        closeFallbackTun()
    }

    // ── Background connection ──────────────────────────────────────────────────

    private fun connectInBackground(configToml: String, startId: Int) {
        val tun = buildTunInterface(configToml)
        if (tun == null) {
            Log.e(TAG, "Failed to establish TUN interface")
            broadcastState(STATE_ERROR, "Failed to establish TUN interface")
            stopSelf(startId)
            return
        }

        if (!VpnClient.nativeLibraryLoaded) {
            Log.w(TAG, "Native library absent — TUN up but no forwarding")
            fallbackTun = tun
            startSession()
            broadcastState(STATE_CONNECTED)
            startForegroundCompat(buildNotification(STATE_CONNECTED))
            return
        }

        try {
            val client = VpnClient(configToml, buildClientListener())
            vpnClient = client
            val started = client.start(tun)
            if (!started) {
                Log.e(TAG, "VpnClient.start() returned false")
                broadcastState(STATE_ERROR, "VPN client failed to start")
                vpnClient = null
                stopSelf(startId)
                return
            }
            registerNetworkCallback()
            Log.i(TAG, "VPN started (native)")
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error starting VPN", e)
            broadcastState(STATE_ERROR, e.message ?: "Unknown error")
            runCatching { tun.close() }
            vpnClient = null
            stopSelf(startId)
        }
    }

    // ── Stop ──────────────────────────────────────────────────────────────────

    private fun stopVpn(startId: Int?) {
        cancelConnectThread()
        unregisterNetworkCallback()
        teardownVpnClient()
        closeFallbackTun()
        activeConfigId = null
        endSession()
        broadcastState(STATE_DISCONNECTED)
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (startId != null) stopSelf(startId) else stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    // ── TUN interface ─────────────────────────────────────────────────────────

    private fun buildTunInterface(configToml: String): ParcelFileDescriptor? = try {
        val builder = Builder()
            .setSession("FireTunnel")
            .setMtu(1500)
            .addAddress("172.20.2.13", 32)
            .addAddress("fdfd:29::2", 64)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
        // Configured upstreams (DoH/DoT/…) are served by the core behind a fake
        // resolver address; without them the core falls back to AdGuard DNS.
        val dnsServers = ConfigFields.tunDnsServers(configToml)
        dnsServers.forEach { builder.addDnsServer(it) }
        Log.i(TAG, "TUN DNS: ${if (dnsServers == ConfigFields.FAKE_DNS) "config upstreams" else "AdGuard DNS"}")
        applyAppRouting(builder)
        builder.establish()
    } catch (e: Exception) {
        Log.e(TAG, "TUN interface error: ${e.message}")
        null
    }

    /** Apply the per-app split tunnelling choice (see [AppRoutingManager]). */
    private fun applyAppRouting(builder: Builder) {
        val plan = AppRoutingManager(this).plan()
        var applied = 0
        for (pkg in plan.allowed) {
            if (tryAddApp(pkg) { builder.addAllowedApplication(it) }) applied++
        }
        if (plan.allowed.isNotEmpty() && applied == 0) {
            // Every selected app was uninstalled: an empty allow-list would route
            // all apps, including FireTunnel itself, so bypass just ourselves instead.
            Log.w(TAG, "No selected apps installed, routing all apps")
            builder.addDisallowedApplication(packageName)
            return
        }
        for (pkg in plan.disallowed) {
            if (tryAddApp(pkg) { builder.addDisallowedApplication(it) }) applied++
        }
        Log.i(TAG, "App routing: ${plan.allowed.size} allowed, ${plan.disallowed.size} bypassed, $applied applied")
    }

    /** Return false if [pkg] is no longer installed. */
    private inline fun tryAddApp(pkg: String, add: (String) -> Unit): Boolean = try {
        add(pkg)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        Log.w(TAG, "Skipping uninstalled app in routing list")
        false
    }

    private fun closeFallbackTun() {
        runCatching { fallbackTun?.close() }
        fallbackTun = null
    }

    // ── VpnClientListener ─────────────────────────────────────────────────────

    private fun buildClientListener() = object : VpnClientListener {

        override fun protectSocket(socket: Int): Boolean = protect(socket)

        override fun verifyCertificate(
            certificate: ByteArray?, rawChain: List<ByteArray?>?
        ): Boolean = true

        override fun onStateChanged(state: Int) {
            val s = runCatching { VpnState.getByCode(state) }.getOrNull() ?: return
            Log.d(TAG, "VpnState → $s")
            when (s) {
                VpnState.CONNECTED -> {
                    startSession()
                    broadcastState(STATE_CONNECTED)
                    startForegroundCompat(buildNotification(STATE_CONNECTED))
                }
                VpnState.DISCONNECTED -> {
                    broadcastState(STATE_DISCONNECTED)
                    android.os.Handler(mainLooper).post { stopVpn(null) }
                }
                VpnState.CONNECTING,
                VpnState.WAITING_RECOVERY,
                VpnState.RECOVERING,
                VpnState.WAITING_FOR_NETWORK -> broadcastState(STATE_CONNECTING)
            }
        }

        override fun onConnectionInfo(info: String) {
            // Fired once per connection — count it instead of broadcasting each one.
            countConnection(info)
        }
    }

    // ── VpnClient teardown ─────────────────────────────────────────────────────

    private fun teardownVpnClient() {
        runCatching { vpnClient?.stop(); vpnClient?.close() }
        vpnClient = null
    }

    // ── Connect thread ─────────────────────────────────────────────────────────

    private fun cancelConnectThread() {
        connectThread?.let { thread ->
            thread.interrupt()
            runCatching { thread.join(3_000) }
        }
        connectThread = null
    }

    // ── Network monitoring ─────────────────────────────────────────────────────

    private fun registerNetworkCallback() {
        val cm = connectivityManager ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { vpnClient?.notifyNetworkChange(true) }
            override fun onLost(network: Network)      { vpnClient?.notifyNetworkChange(false) }
        }
        runCatching {
            cm.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build(), cb
            )
        }
        networkCallback = cb
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            runCatching { connectivityManager?.unregisterNetworkCallback(it) }
            networkCallback = null
        }
    }

    // ── Notifications ─────────────────────────────────────────────────────────

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(state: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.vpn_channel_name),
                    NotificationManager.IMPORTANCE_LOW)
            )
        }
        val tap = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val disconnectPi = PendingIntent.getService(
            this, 1,
            Intent(this, FireTunnelVpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_IMMUTABLE
        )
        val text = if (state == STATE_CONNECTED) getString(R.string.vpn_notification_connected)
                   else getString(R.string.vpn_notification_connecting)

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentIntent(tap)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(null, getString(R.string.disconnect), disconnectPi).build()
            )
            .build()
    }

    // ── Broadcast ─────────────────────────────────────────────────────────────

    private fun broadcastState(vpnState: String, error: String? = null) {
        lastKnownState = vpnState
        sendBroadcast(Intent(BROADCAST_STATE).apply {
            putExtra(EXTRA_STATE, vpnState)
            error?.let { putExtra(EXTRA_ERROR_MSG, it) }
            if (vpnState == STATE_CONNECTED && sessionStartedAt > 0L) {
                putExtra(EXTRA_CONNECTED_AT, sessionStartedAt)
            }
            setPackage(packageName)
        })
    }
}

/** Snapshot of the current VPN session, see [FireTunnelVpnService.sessionStats]. */
data class SessionStats(
    val connectedAt: Long,
    val rxBytes: Long?,
    val txBytes: Long?,
    val tunnelConnections: Long,
    val bypassConnections: Long
)
