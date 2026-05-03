package com.trusttunnel.android

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.snackbar.Snackbar
import com.trusttunnel.android.data.ConfigManager
import com.trusttunnel.android.data.VpnConfig

class MainActivity : AppCompatActivity() {

    private lateinit var configManager: ConfigManager
    private lateinit var statusCard: MaterialCardView
    private lateinit var statusLabel: TextView
    private lateinit var statusText: TextView
    private lateinit var connectionButton: MaterialButton
    private lateinit var configSpinner: Spinner
    private lateinit var qrButton: MaterialButton
    private lateinit var logsButton: MaterialButton
    private lateinit var settingsButton: MaterialButton
    private lateinit var statsText: TextView
    private lateinit var deleteConfigButton: MaterialButton

    private var configs: List<VpnConfig> = emptyList()
    private var vpnState: String = TrustTunnelVpnService.STATE_DISCONNECTED

    // Uptime tracking
    private val uptimeHandler = Handler(Looper.getMainLooper())
    private var connectedAt: Long = 0L
    private val uptimeTicker = object : Runnable {
        override fun run() {
            if (vpnState == TrustTunnelVpnService.STATE_CONNECTED && connectedAt > 0L) {
                val elapsed = (System.currentTimeMillis() - connectedAt) / 1000L
                val h = elapsed / 3600
                val m = (elapsed % 3600) / 60
                val s = elapsed % 60
                val uptimeStr = if (h > 0) "%d:%02d:%02d".format(h, m, s)
                                else "%02d:%02d".format(m, s)
                statsText.text = getString(R.string.uptime_label, uptimeStr)
                uptimeHandler.postDelayed(this, 1_000)
            }
        }
    }

    companion object {
        private const val REQ_CAMERA = 101
        private const val REQ_NOTIFY = 102
    }

    // ── VPN permission request ─────────────────────────────────────────────────
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpn()
        } else {
            showSnackbar(getString(R.string.vpn_permission_required))
        }
    }

    // ── QR scan result ─────────────────────────────────────────────────────────
    private val qrLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            loadConfigs() // refresh spinner with the new config
        }
    }

    // ── VPN state broadcast receiver ───────────────────────────────────────────
    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val state = intent.getStringExtra(TrustTunnelVpnService.EXTRA_STATE) ?: return
            vpnState = state

            // Capture connection time for uptime counter
            if (state == TrustTunnelVpnService.STATE_CONNECTED) {
                val ts = intent.getLongExtra(TrustTunnelVpnService.EXTRA_CONNECTED_AT, 0L)
                if (ts > 0L) connectedAt = ts
                uptimeHandler.removeCallbacks(uptimeTicker)
                uptimeHandler.post(uptimeTicker)
            } else if (state == TrustTunnelVpnService.STATE_DISCONNECTED ||
                       state == TrustTunnelVpnService.STATE_ERROR) {
                uptimeHandler.removeCallbacks(uptimeTicker)
                connectedAt = 0L
            }

            updateStatusUI(state)

            // Show connection stats (JSON blob from native core) if present
            val stats = intent.getStringExtra(TrustTunnelVpnService.EXTRA_STATS)
            if (!stats.isNullOrBlank()) {
                updateStats(stats)
            }
        }
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        configManager = ConfigManager(this)

        bindViews()
        setupListeners()
        loadConfigs()
        requestNotificationPermission()
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(TrustTunnelVpnService.BROADCAST_STATE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnStateReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(vpnStateReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        runCatching { unregisterReceiver(vpnStateReceiver) }
    }

    override fun onDestroy() {
        super.onDestroy()
        uptimeHandler.removeCallbacks(uptimeTicker)
    }

    // ── View setup ─────────────────────────────────────────────────────────────

    private fun bindViews() {
        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)

        statusCard        = findViewById(R.id.statusCard)
        statusLabel       = findViewById(R.id.statusLabel)
        statusText        = findViewById(R.id.statusText)
        connectionButton  = findViewById(R.id.connectionButton)
        configSpinner     = findViewById(R.id.configSpinner)
        qrButton          = findViewById(R.id.qrButton)
        logsButton        = findViewById(R.id.logsButton)
        settingsButton    = findViewById(R.id.settingsButton)
        statsText         = findViewById(R.id.statsText)
        deleteConfigButton = findViewById(R.id.deleteConfigButton)
    }

    private fun setupListeners() {
        connectionButton.setOnClickListener { onConnectClicked() }
        qrButton.setOnClickListener { openQrScanner() }
        logsButton.setOnClickListener {
            startActivity(Intent(this, LogActivity::class.java))
        }
        settingsButton.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
        deleteConfigButton.setOnClickListener { confirmDeleteConfig() }
    }

    // ── Config loading ─────────────────────────────────────────────────────────

    private fun loadConfigs() {
        configs = configManager.getConfigs()
        val names = if (configs.isEmpty()) {
            listOf(getString(R.string.no_configs))
        } else {
            configs.map { it.name }
        }
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, names)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        configSpinner.adapter = adapter
        val hasConfigs = configs.isNotEmpty()
        connectionButton.isEnabled = hasConfigs
        deleteConfigButton.isEnabled = hasConfigs
    }

    // ── Connect / disconnect ───────────────────────────────────────────────────

    private fun onConnectClicked() {
        if (vpnState == TrustTunnelVpnService.STATE_CONNECTED ||
            vpnState == TrustTunnelVpnService.STATE_CONNECTING
        ) {
            stopVpn()
        } else {
            prepareAndConnect()
        }
    }

    private fun prepareAndConnect() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val idx = configSpinner.selectedItemPosition
        if (idx < 0 || idx >= configs.size) {
            showSnackbar(getString(R.string.vpn_select_config))
            return
        }
        val config = configs[idx]
        val intent = Intent(this, TrustTunnelVpnService::class.java).apply {
            action = TrustTunnelVpnService.ACTION_CONNECT
            putExtra(TrustTunnelVpnService.EXTRA_CONFIG_TOML, config.rawToml)
        }
        startForegroundService(intent)
        updateStatusUI(TrustTunnelVpnService.STATE_CONNECTING)
    }

    private fun stopVpn() {
        val intent = Intent(this, TrustTunnelVpnService::class.java).apply {
            action = TrustTunnelVpnService.ACTION_DISCONNECT
        }
        startService(intent)
        updateStatusUI(TrustTunnelVpnService.STATE_DISCONNECTED)
    }

    // ── Delete config ──────────────────────────────────────────────────────────

    private fun confirmDeleteConfig() {
        val idx = configSpinner.selectedItemPosition
        if (idx < 0 || idx >= configs.size) return
        val config = configs[idx]
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.delete_config_title))
            .setMessage(getString(R.string.delete_config_message, config.name))
            .setPositiveButton(getString(R.string.delete)) { _, _ ->
                configManager.deleteConfig(config.id)
                loadConfigs()
                showSnackbar(getString(R.string.config_deleted, config.name))
            }
            .setNegativeButton(getString(android.R.string.cancel), null)
            .show()
    }

    // ── Status UI ──────────────────────────────────────────────────────────────

    private fun updateStatusUI(state: String) {
        when (state) {
            TrustTunnelVpnService.STATE_CONNECTED -> {
                statusLabel.text = getString(R.string.status_connected)
                statusText.text  = getString(R.string.connected)
                connectionButton.text = getString(R.string.disconnect)
                statusCard.setCardBackgroundColor(getColor(R.color.claude_green_container))
                statusText.setTextColor(getColor(R.color.claude_green))
            }
            TrustTunnelVpnService.STATE_CONNECTING -> {
                statusLabel.text = getString(R.string.status_connecting)
                statusText.text  = getString(R.string.connecting)
                connectionButton.text = getString(R.string.disconnect)
                statusCard.setCardBackgroundColor(getColor(R.color.claude_surface_variant))
                statusText.setTextColor(getColor(R.color.claude_gray))
            }
            TrustTunnelVpnService.STATE_ERROR -> {
                statusLabel.text = getString(R.string.status_disconnected)
                statusText.text  = getString(R.string.disconnected)
                connectionButton.text = getString(R.string.connect)
                statusCard.setCardBackgroundColor(getColor(R.color.claude_red_container))
                statusText.setTextColor(getColor(R.color.claude_red))
                statsText.text = getString(R.string.no_stats)
            }
            else -> { // DISCONNECTED
                statusLabel.text = getString(R.string.status_disconnected)
                statusText.text  = getString(R.string.disconnected)
                connectionButton.text = getString(R.string.connect)
                statusCard.setCardBackgroundColor(getColor(R.color.claude_surface_variant))
                statusText.setTextColor(getColor(R.color.claude_on_surface))
                statsText.text = getString(R.string.no_stats)
            }
        }
    }

    // ── Stats / uptime display ────────────────────────────────────────────────

    private fun updateStats(json: String) {
        runCatching {
            fun extract(key: String): Long? =
                Regex(""""$key"\s*:\s*(\d+)""").find(json)?.groupValues?.get(1)?.toLong()

            val rx = extract("bytesReceived") ?: extract("rx") ?: extract("received")
            val tx = extract("bytesSent")     ?: extract("tx") ?: extract("sent")

            if (rx != null || tx != null) {
                val rxStr = rx?.let { formatBytes(it) } ?: "—"
                val txStr = tx?.let { formatBytes(it) } ?: "—"
                statsText.text = "↓ $rxStr  ↑ $txStr"
            }
        }
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1_024L           -> "$bytes B"
        bytes < 1_048_576L       -> "${"%.1f".format(bytes / 1_024.0)} KB"
        bytes < 1_073_741_824L   -> "${"%.1f".format(bytes / 1_048_576.0)} MB"
        else                     -> "${"%.2f".format(bytes / 1_073_741_824.0)} GB"
    }

    // ── QR scanner ─────────────────────────────────────────────────────────────

    private fun openQrScanner() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                this, arrayOf(Manifest.permission.CAMERA), REQ_CAMERA
            )
        } else {
            qrLauncher.launch(Intent(this, QRScannerActivity::class.java))
        }
    }

    // ── Permissions ───────────────────────────────────────────────────────────

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFY
                )
            }
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_CAMERA &&
            grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
        ) {
            qrLauncher.launch(Intent(this, QRScannerActivity::class.java))
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun showSnackbar(message: String) {
        Snackbar.make(findViewById(android.R.id.content), message, Snackbar.LENGTH_SHORT).show()
    }
}
