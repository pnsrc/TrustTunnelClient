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
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
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
    private lateinit var settingsButton: MaterialButton
    private lateinit var statsText: TextView

    private var configs: List<VpnConfig> = emptyList()
    private var vpnState: String = TrustTunnelVpnService.STATE_DISCONNECTED

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

    // ── View setup ─────────────────────────────────────────────────────────────

    private fun bindViews() {
        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)

        statusCard       = findViewById(R.id.statusCard)
        statusLabel      = findViewById(R.id.statusLabel)
        statusText       = findViewById(R.id.statusText)
        connectionButton = findViewById(R.id.connectionButton)
        configSpinner    = findViewById(R.id.configSpinner)
        qrButton         = findViewById(R.id.qrButton)
        settingsButton   = findViewById(R.id.settingsButton)
        statsText        = findViewById(R.id.statsText)
    }

    private fun setupListeners() {
        connectionButton.setOnClickListener { onConnectClicked() }
        qrButton.setOnClickListener { openQrScanner() }
        settingsButton.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
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
        connectionButton.isEnabled = configs.isNotEmpty()
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
            // Need to ask user for VPN permission
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            // Already prepared
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

    // ── Stats display ─────────────────────────────────────────────────────────

    /**
     * Parse a simplified stats summary from the JSON blob emitted by the native core.
     * We look for "bytesReceived" and "bytesSent" (or similar fields).
     */
    private fun updateStats(json: String) {
        runCatching {
            // Simple regex-based extraction to avoid requiring a JSON dependency
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
        bytes < 1_024L           -> "${bytes} B"
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
