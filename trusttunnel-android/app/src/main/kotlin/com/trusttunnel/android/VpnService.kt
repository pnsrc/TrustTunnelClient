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
 * Threading model
 * ───────────────
 * Android requires [startForeground] to be called on the main thread within
 * 5 s of [startForegroundService].  All blocking work (TUN interface creation,
 * native client start) therefore runs on a dedicated "vpn-connect" background
 * thread.  Only the notification and broadcast calls happen on the main thread.
 *
 * Native library
 * ──────────────
 * [VpnClient.tryLoadLibrary] is called during [onCreate].  If it fails
 * (library absent, e.g. debug build without NDK), the service establishes the
 * TUN interface as a no-op tunnel — Android shows the VPN key icon and the app
 * keeps running, but traffic is not forwarded until the .so is compiled and
 * linked.
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

    // Accessed from both main thread and connect thread — always via @Volatile
    @Volatile private var vpnClient: VpnClient? = null
    @Volatile private var fallbackTun: ParcelFileDescriptor? = null
    @Volatile private var connectThread: Thread? = null

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        // Load native library once; safe to call if already loaded.
        VpnClient.tryLoadLibrary()
        connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val toml = intent.getStringExtra(EXTRA_CONFIG_TOML) ?: ""

                // ① Call startForeground IMMEDIATELY on the main thread.
                //   Android throws ForegroundServiceDidNotStartInTimeException
                //   if this is delayed past ~5 s.
                broadcastState(STATE_CONNECTING)
                startForegroundCompat(buildNotification(STATE_CONNECTING))

                // ② Do all blocking VPN setup on a background thread.
                cancelConnectThread()
                connectThread = Thread(
                    { connectInBackground(toml, startId) },
                    "vpn-connect"
                ).also { it.start() }
            }

            ACTION_DISCONNECT -> stopVpn(startId)

            else -> {
                // Service restarted by system with null intent (START_NOT_STICKY
                // prevents this, but handle it defensively).
                stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked by user")
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
        val tun = buildTunInterface()
        if (tun == null) {
            Log.e(TAG, "Failed to establish TUN interface")
            broadcastState(STATE_ERROR, "Failed to establish TUN interface")
            stopSelf(startId)
            return
        }

        if (!VpnClient.nativeLibraryLoaded) {
            // No native library → keep TUN open as a stub so Android shows the
            // VPN key.  Traffic is NOT forwarded.
            Log.w(TAG, "Native library absent — TUN up but no forwarding")
            fallbackTun = tun
            broadcastState(STATE_CONNECTED)
            startForegroundCompat(buildNotification(STATE_CONNECTED))
            return
        }

        // Native library is loaded — start the real VPN client.
        try {
            val client = VpnClient(configToml, buildClientListener())
            vpnClient = client
            // VpnClient.start() transfers ownership of tun via detachFd().
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
            // Connected state is reported via onStateChanged callback.
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error starting VPN", e)
            broadcastState(STATE_ERROR, e.message ?: "Unknown error")
            runCatching { tun.close() }
            vpnClient = null
            stopSelf(startId)
        }
    }

    // ── VPN stop ──────────────────────────────────────────────────────────────

    private fun stopVpn(startId: Int?) {
        cancelConnectThread()
        unregisterNetworkCallback()
        teardownVpnClient()
        closeFallbackTun()
        broadcastState(STATE_DISCONNECTED)
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (startId != null) stopSelf(startId) else stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    // ── TUN interface ─────────────────────────────────────────────────────────

    private fun buildTunInterface(): ParcelFileDescriptor? = try {
        Builder()
            .setSession("TrustTunnel")
            .setMtu(1500)
            .addAddress("172.20.2.13", 32)
            .addAddress("fdfd:29::2", 64)
            // DNS — overridden by native core once it starts.
            // Using AdGuard DNS as a safe default.
            .addDnsServer("46.243.231.30")
            .addDnsServer("46.243.231.31")
            .addDnsServer("2a10:50c0::2:ff")
            // Route all traffic through the tunnel
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // Exclude our own process so the VPN socket isn't tunnelled
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
        ): Boolean = true

        override fun onStateChanged(state: Int) {
            val s = runCatching { VpnState.getByCode(state) }.getOrNull() ?: return
            Log.d(TAG, "VpnState → $s")
            when (s) {
                VpnState.CONNECTED -> {
                    broadcastState(STATE_CONNECTED)
                    startForegroundCompat(buildNotification(STATE_CONNECTED))
                }
                VpnState.DISCONNECTED        -> broadcastState(STATE_DISCONNECTED)
                VpnState.CONNECTING          -> broadcastState(STATE_CONNECTING)
                VpnState.WAITING_RECOVERY,
                VpnState.RECOVERING,
                VpnState.WAITING_FOR_NETWORK -> broadcastState(STATE_CONNECTING)
            }
        }

        override fun onConnectionInfo(info: String) {
            broadcastState(STATE_CONNECTED, stats = info)
        }
    }

    // ── VpnClient teardown ─────────────────────────────────────────────────────

    private fun teardownVpnClient() {
        runCatching {
            vpnClient?.stop()
            vpnClient?.close()
        }
        vpnClient = null
    }

    // ── Connect thread ─────────────────────────────────────────────────────────

    private fun cancelConnectThread() {
        connectThread?.interrupt()
        connectThread = null
    }

    // ── Network monitoring ─────────────────────────────────────────────────────

    private fun registerNetworkCallback() {
        val cm = connectivityManager ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.d(TAG, "Network available")
                vpnClient?.notifyNetworkChange(true)
            }
            override fun onLost(network: Network) {
                Log.d(TAG, "Network lost")
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
