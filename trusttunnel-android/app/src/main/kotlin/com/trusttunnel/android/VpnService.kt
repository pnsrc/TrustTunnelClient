package com.trusttunnel.android

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.util.Log

class VpnService : Service() {
    private val binder = VpnBinder()
    private var isConnected = false

    companion object {
        private const val TAG = "TrustTunnelVpn"
    }

    inner class VpnBinder : Binder() {
        fun getService(): VpnService = this@VpnService
    }

    override fun onBind(intent: Intent?): IBinder {
        return binder
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "CONNECT" -> {
                connect()
            }
            "DISCONNECT" -> {
                disconnect()
            }
        }
        return START_STICKY
    }

    private fun connect() {
        try {
            // Initialize VPN connection using trusttunnel-core
            isConnected = true
            Log.d(TAG, "VPN connected")
        } catch (e: Exception) {
            Log.e(TAG, "Connection error: ${e.message}")
        }
    }

    private fun disconnect() {
        try {
            // Cleanup VPN connection
            isConnected = false
            Log.d(TAG, "VPN disconnected")
        } catch (e: Exception) {
            Log.e(TAG, "Disconnection error: ${e.message}")
        }
    }

    fun isVpnConnected(): Boolean = isConnected
}
