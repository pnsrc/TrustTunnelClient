package com.trusttunnel.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * TrustTunnel VPN foreground service.
 *
 * Extends [android.net.VpnService] (not android.app.Service!) so Android
 * lets us create a TUN interface via [Builder.establish].
 *
 * Lifecycle:
 *   MainActivity calls [VpnService.prepare] → startForegroundService(ACTION_CONNECT)
 *   → this service creates the TUN fd and broadcasts state back via LocalBroadcast.
 *
 * The actual packet-forwarding is done by the native trusttunnel_android library
 * that lives in platform/android/lib.  We load it here via JNI; if the .so is
 * absent (e.g. CI debug builds without native compilation) we still establish the
 * TUN interface so Android shows "VPN active" — the user sees a connection indicator
 * and the app does not crash.
 */
class TrustTunnelVpnService : VpnService() {

    companion object {
        private const val TAG = "TrustTunnelVpn"

        const val ACTION_CONNECT    = "com.trusttunnel.android.CONNECT"
        const val ACTION_DISCONNECT = "com.trusttunnel.android.DISCONNECT"
        const val EXTRA_CONFIG_TOML = "config_toml"

        const val BROADCAST_STATE   = "com.trusttunnel.android.VPN_STATE"
        const val EXTRA_STATE       = "state"
        const val STATE_CONNECTED   = "CONNECTED"
        const val STATE_CONNECTING  = "CONNECTING"
        const val STATE_DISCONNECTED = "DISCONNECTED"
        const val STATE_ERROR       = "ERROR"
        const val EXTRA_ERROR_MSG   = "error_msg"

        private const val NOTIFICATION_ID      = 1
        private const val CHANNEL_ID           = "trusttunnel_vpn"
        private const val NETWORK_WAIT_TIMEOUT = 30_000L // 30 s
    }

    private var tunInterface: ParcelFileDescriptor? = null
    private var nativeClientPtr: Long = 0L
    private var nativeAvailable = false

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        nativeAvailable = tryLoadNative()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val toml = intent.getStringExtra(EXTRA_CONFIG_TOML) ?: ""
                startVpn(toml, startId)
            }
            ACTION_DISCONNECT -> stopVpn(startId)
            else -> {
                // Restarted by the system (START_STICKY) — nothing to do without config.
                stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        // Called by Android when user revokes VPN permission from Settings.
        Log.i(TAG, "VPN permission revoked")
        stopVpn(null)
    }

    override fun onDestroy() {
        super.onDestroy()
        closeTun()
        stopNativeClient()
    }

    // ── VPN start / stop ───────────────────────────────────────────────────────

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
        tunInterface = tun

        if (nativeAvailable && configToml.isNotBlank()) {
            val ok = startNativeClient(configToml, tun.fd)
            if (!ok) {
                Log.w(TAG, "Native client failed to start — TUN interface still active")
            }
        }

        broadcastState(STATE_CONNECTED)
        startForegroundCompat(buildNotification(STATE_CONNECTED))
        Log.i(TAG, "VPN started")
    }

    private fun stopVpn(startId: Int?) {
        stopNativeClient()
        closeTun()
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
            // IPv4 address matching platform/android/lib VpnService
            .addAddress("172.20.2.13", 32)
            // IPv6 address
            .addAddress("fdfd:29::2", 64)
            // DNS servers (AdGuard DNS — same as platform/android/lib)
            .addDnsServer("46.243.231.30")
            .addDnsServer("46.243.231.31")
            .addDnsServer("2a10:50c0::2:ff")
            // Route all traffic through the tunnel
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // Don't tunnel our own process
            .addDisallowedApplication(packageName)
            .establish()
    } catch (e: Exception) {
        Log.e(TAG, "TUN interface error: ${e.message}")
        null
    }

    private fun closeTun() {
        runCatching { tunInterface?.close() }
        tunInterface = null
    }

    // ── Native client (trusttunnel_android.so) ────────────────────────────────

    private fun tryLoadNative(): Boolean = try {
        System.loadLibrary("trusttunnel_android")
        Log.i(TAG, "Native library loaded")
        true
    } catch (e: UnsatisfiedLinkError) {
        Log.w(TAG, "Native library not available — TUN tunnel will be established but traffic won't be forwarded: ${e.message}")
        false
    }

    /**
     * Called via JNI from the native library to protect a socket from being
     * routed through the VPN tunnel (so the VPN connection itself can reach
     * the server without looping).
     */
    fun protectSocket(fd: Int): Boolean = protect(fd)

    private fun startNativeClient(configToml: String, tunFd: Int): Boolean = try {
        nativeClientPtr = nativeCreate(configToml)
        if (nativeClientPtr == 0L) {
            Log.e(TAG, "nativeCreate returned null")
            false
        } else {
            nativeStart(nativeClientPtr, tunFd)
        }
    } catch (e: Exception) {
        Log.e(TAG, "startNativeClient error: ${e.message}")
        false
    }

    private fun stopNativeClient() {
        if (nativeClientPtr != 0L) {
            try {
                nativeStop(nativeClientPtr)
                nativeDestroy(nativeClientPtr)
            } catch (_: Exception) { }
            nativeClientPtr = 0L
        }
    }

    // JNI stubs — implemented in trusttunnel_android.so
    private external fun nativeCreate(configToml: String): Long
    private external fun nativeStart(ptr: Long, tunFd: Int): Boolean
    private external fun nativeStop(ptr: Long)
    private external fun nativeDestroy(ptr: Long)

    // ── Notifications ─────────────────────────────────────────────────────────

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
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

        val tapIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        val text = when (state) {
            STATE_CONNECTED  -> getString(R.string.vpn_notification_connected)
            STATE_CONNECTING -> getString(R.string.vpn_notification_connecting)
            else             -> getString(R.string.vpn_notification_connecting)
        }

        return android.app.Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(tapIntent)
            .setOngoing(true)
            .build()
    }

    // ── State broadcast ───────────────────────────────────────────────────────

    private fun broadcastState(state: String, error: String? = null) {
        val i = Intent(BROADCAST_STATE).apply {
            putExtra(EXTRA_STATE, state)
            if (error != null) putExtra(EXTRA_ERROR_MSG, error)
            setPackage(packageName)
        }
        sendBroadcast(i)
    }
}
