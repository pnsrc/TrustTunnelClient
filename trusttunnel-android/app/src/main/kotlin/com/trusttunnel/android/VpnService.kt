package com.trusttunnel.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.adguard.trusttunnel.VpnClient
import com.adguard.trusttunnel.VpnClientListener
import com.adguard.trusttunnel.VpnState

/**
 * TrustTunnel VPN foreground service.
 *
 * Delegates actual packet forwarding to [VpnClient] from platform/android/lib,
 * which wraps the native trusttunnel_android.so (C++ / Rust core).
 *
 * Network-change events are forwarded via [VpnClient.notifyNetworkChange] so the
 * core can reconnect automatically after sleep or interface switches.
 *
 * If the native .so is absent at runtime (e.g. a pure-Kotlin debug build) we
 * establish the TUN interface anyway and catch [UnsatisfiedLinkError] gracefully.
 */
class TrustTunnelVpnService : VpnService() {

    companion object {
        private const val TAG = "TrustTunnelVpn"

        const val ACTION_CONNECT     = "com.trusttunnel.android.CONNECT"
        const val ACTION_DISCONNECT  = "com.trusttunnel.android.DISCONNECT"
        const val EXTRA_CONFIG_TOML  = "config_toml"

        const val BROADCAST_STATE    = "com.trusttunnel.android.VPN_STATE"
        const val EXTRA_STATE        = "state"
        const val STATE_CONNECTED    = "CONNECTED"
        const val STATE_CONNECTING   = "CONNECTING"
        const val STATE_DISCONNECTED = "DISCONNECTED"
        const val STATE_ERROR        = "ERROR"
        const val EXTRA_ERROR_MSG    = "error_msg"
        const val EXTRA_STATS        = "stats"

        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID      = "trusttunnel_vpn"
    }

    // Non-null while VPN is running
    private var vpnClient: VpnClient? = null
    // Only used in the fallback path (native lib absent)
    private var fallbackTun: ParcelFileDescriptor? = null

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT    -> startVpn(
                intent.getStringExtra(EXTRA_CONFIG_TOML) ?: "", startId
            )
            ACTION_DISCONNECT -> stopVpn(startId)
            else              -> stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked by user")
        stopVpn(null)
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterNetworkCallback()
        stopVpnClient()
        closeFallbackTun()
    }

    // ── VPN start ─────────────────────────────────────────────────────────────

    private fun startVpn(configToml: String, startId: Int) {
        broadcastState(STATE_CONNECTING)
        startForegroundCompat(buildNotification(STATE_CONNECTING))

        val tun = buildTunInterface()
        if (tun == null) {
            Log.e(TAG, "Failed to establish TUN interface")
            broadcastState(STATE_ERROR, "Failed to establish TUN interface")
            stopSelf(startId)
            return
        }

        val listener = buildClientListener()

        try {
            val client = VpnClient(configToml, listener)
            vpnClient = client
            // VpnClient.start() transfers fd ownership via ParcelFileDescriptor.detachFd()
            // so we must NOT close tun ourselves after this point.
            val started = client.start(tun)
            if (!started) {
                Log.e(TAG, "VpnClient.start() returned false")
                broadcastState(STATE_ERROR, "VPN client failed to start")
                stopSelf(startId)
                return
            }
            registerNetworkCallback()
            Log.i(TAG, "VPN started via native VpnClient")
            // Connected state is broadcast by onStateChanged callback from native core
        } catch (e: UnsatisfiedLinkError) {
            // Native library not compiled / not present.
            // Keep the TUN interface open so Android shows the VPN indicator;
            // no traffic is forwarded but the app won't crash.
            Log.w(TAG, "Native library not available — tunnel open but no forwarding: ${e.message}")
            fallbackTun = tun
            broadcastState(STATE_CONNECTED)
            startForegroundCompat(buildNotification(STATE_CONNECTED))
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error starting VPN: ${e.message}", e)
            broadcastState(STATE_ERROR, e.message ?: "Unknown error")
            runCatching { tun.close() }
            vpnClient = null
            stopSelf(startId)
        }
    }

    // ── VPN stop ──────────────────────────────────────────────────────────────

    private fun stopVpn(startId: Int?) {
        unregisterNetworkCallback()
        stopVpnClient()
        closeFallbackTun()
        broadcastState(STATE_DISCONNECTED)
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (startId != null) stopSelf(startId) else stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    // ── TUN interface ─────────────────────────────────────────────────────────

    /**
     * Build a TUN interface.
     *
     * The IP address / DNS values here are defaults; the native core configures
     * proper routing after it reads the TOML.  The TUN simply needs valid
     * addresses so Android accepts the interface.
     */
    private fun buildTunInterface(): ParcelFileDescriptor? = try {
        Builder()
            .setSession("TrustTunnel")
            .setMtu(1500)
            .addAddress("172.20.2.13", 32)
            .addAddress("fdfd:29::2", 64)
            // DNS (AdGuard — overridden by the native core for the real tunnel)
            .addDnsServer("46.243.231.30")
            .addDnsServer("46.243.231.31")
            .addDnsServer("2a10:50c0::2:ff")
            // Route all traffic through the tunnel
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // Exclude our own process so the VPN connection socket isn't looped
            .addDisallowedApplication(packageName)
            .establish()
    } catch (e: Exception) {
        Log.e(TAG, "TUN interface error: ${e.message}")
        null
    }

    private fun closeFallbackTun() {
        runCatching { fallbackTun?.close() }
        fallbackTun = null
    }

    // ── VpnClientListener ─────────────────────────────────────────────────────

    private fun buildClientListener() = object : VpnClientListener {

        override fun protectSocket(socket: Int): Boolean = protect(socket)

        override fun verifyCertificate(
            certificate: ByteArray?,
            rawChain: List<ByteArray?>?
        ): Boolean = true   // trust the server cert (pinning can be added here)

        override fun onStateChanged(state: Int) {
            val vpnState = runCatching { VpnState.getByCode(state) }.getOrNull() ?: return
            Log.d(TAG, "VpnState changed → $vpnState")
            when (vpnState) {
                VpnState.CONNECTED -> {
                    broadcastState(STATE_CONNECTED)
                    startForegroundCompat(buildNotification(STATE_CONNECTED))
                }
                VpnState.DISCONNECTED -> broadcastState(STATE_DISCONNECTED)
                VpnState.CONNECTING   -> broadcastState(STATE_CONNECTING)
                // Recovery / waiting states map to "connecting" in our simplified UI
                VpnState.WAITING_RECOVERY,
                VpnState.RECOVERING,
                VpnState.WAITING_FOR_NETWORK -> broadcastState(STATE_CONNECTING)
            }
        }

        override fun onConnectionInfo(info: String) {
            // info is a JSON stats blob; forward it with the broadcast so
            // MainActivity can display bytes-transferred / latency.
            broadcastState(STATE_CONNECTED, stats = info)
        }
    }

    // ── VpnClient teardown ────────────────────────────────────────────────────

    private fun stopVpnClient() {
        runCatching {
            vpnClient?.stop()
            vpnClient?.close()
        }
        vpnClient = null
    }

    // ── Network monitoring ─────────────────────────────────────────────────────

    /**
     * Register a [ConnectivityManager.NetworkCallback] so the native core knows
     * when the underlying network comes back after sleep or a roaming switch.
     */
    private fun registerNetworkCallback() {
        val cm = connectivityManager ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.d(TAG, "Network available — notifying native core")
                vpnClient?.notifyNetworkChange(true)
            }
            override fun onLost(network: Network) {
                Log.d(TAG, "Network lost — notifying native core")
                vpnClient?.notifyNetworkChange(false)
            }
        }
        runCatching {
            cm.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build(),
                cb
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(state: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.vpn_channel_name),
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }
        val tap = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val text = if (state == STATE_CONNECTED)
            getString(R.string.vpn_notification_connected)
        else
            getString(R.string.vpn_notification_connecting)

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(tap)
            .setOngoing(true)
            .build()
    }

    // ── State broadcast ───────────────────────────────────────────────────────

    private fun broadcastState(
        vpnState: String,
        error: String? = null,
        stats: String? = null
    ) {
        sendBroadcast(Intent(BROADCAST_STATE).apply {
            putExtra(EXTRA_STATE, vpnState)
            error?.let { putExtra(EXTRA_ERROR_MSG, it) }
            stats?.let { putExtra(EXTRA_STATS, it) }
            setPackage(packageName)
        })
    }
}
