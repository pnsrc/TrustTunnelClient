package me.pnsrc.firetunnel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.res.ColorStateList
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.ImageView
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.widget.ImageViewCompat
import androidx.fragment.app.Fragment
import com.google.android.material.R as MaterialR
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.color.MaterialColors
import com.google.android.material.snackbar.Snackbar
import me.pnsrc.firetunnel.data.ConfigManager
import me.pnsrc.firetunnel.data.VpnConfig

class HomeFragment : Fragment() {

    private lateinit var configManager: ConfigManager
    private lateinit var statusCard: MaterialCardView
    private lateinit var statusIcon: ImageView
    private lateinit var statusLabel: TextView
    private lateinit var statusText: TextView
    private lateinit var connectionButton: MaterialButton
    private lateinit var configSpinner: Spinner
    private lateinit var statsText: TextView
    private lateinit var deleteConfigButton: MaterialButton

    private var configs: List<VpnConfig> = emptyList()
    private var vpnState: String = FireTunnelVpnService.STATE_DISCONNECTED

    // Uptime counter
    private val uptimeHandler = Handler(Looper.getMainLooper())
    private var connectedAt: Long = 0L
    private val uptimeTicker = object : Runnable {
        override fun run() {
            if (vpnState == FireTunnelVpnService.STATE_CONNECTED && connectedAt > 0L) {
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

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) startVpn()
        else showSnackbar(getString(R.string.vpn_permission_required))
    }

    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val state = intent.getStringExtra(FireTunnelVpnService.EXTRA_STATE) ?: return
            vpnState = state

            when (state) {
                FireTunnelVpnService.STATE_CONNECTED -> {
                    val ts = intent.getLongExtra(FireTunnelVpnService.EXTRA_CONNECTED_AT, 0L)
                    if (ts > 0L) connectedAt = ts
                    uptimeHandler.removeCallbacks(uptimeTicker)
                    uptimeHandler.post(uptimeTicker)
                }
                FireTunnelVpnService.STATE_DISCONNECTED,
                FireTunnelVpnService.STATE_ERROR -> {
                    uptimeHandler.removeCallbacks(uptimeTicker)
                    connectedAt = 0L
                }
            }

            updateStatusUI(state)

            val stats = intent.getStringExtra(FireTunnelVpnService.EXTRA_STATS)
            if (!stats.isNullOrBlank()) updateStats(stats)
        }
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_home, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        configManager = ConfigManager(requireContext())

        statusCard        = view.findViewById(R.id.statusCard)
        statusIcon        = view.findViewById(R.id.statusIcon)
        statusLabel       = view.findViewById(R.id.statusLabel)
        statusText        = view.findViewById(R.id.statusText)
        connectionButton  = view.findViewById(R.id.connectionButton)
        configSpinner     = view.findViewById(R.id.configSpinner)
        statsText         = view.findViewById(R.id.statsText)
        deleteConfigButton = view.findViewById(R.id.deleteConfigButton)

        connectionButton.setOnClickListener { onConnectClicked() }
        deleteConfigButton.setOnClickListener { confirmDeleteConfig() }

        // Restore last known state (prevents blank UI after tab switch)
        updateStatusUI(FireTunnelVpnService.lastKnownState)
        loadConfigs()
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(FireTunnelVpnService.BROADCAST_STATE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requireContext().registerReceiver(
                vpnStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED
            )
        } else {
            requireContext().registerReceiver(vpnStateReceiver, filter)
        }
        loadConfigs()
    }

    override fun onPause() {
        super.onPause()
        runCatching { requireContext().unregisterReceiver(vpnStateReceiver) }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        uptimeHandler.removeCallbacks(uptimeTicker)
    }

    // ── Config loading ─────────────────────────────────────────────────────────

    private fun loadConfigs() {
        if (!isAdded) return
        configs = configManager.getConfigs()
        val names = if (configs.isEmpty()) listOf(getString(R.string.no_configs))
                    else configs.map { it.name }
        val adapter = ArrayAdapter(requireContext(), android.R.layout.simple_spinner_item, names)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        configSpinner.adapter = adapter
        connectionButton.isEnabled = configs.isNotEmpty()
        deleteConfigButton.isEnabled = configs.isNotEmpty()
    }

    // ── Connect / disconnect ───────────────────────────────────────────────────

    private fun onConnectClicked() {
        if (vpnState == FireTunnelVpnService.STATE_CONNECTED ||
            vpnState == FireTunnelVpnService.STATE_CONNECTING
        ) {
            stopVpn()
        } else {
            prepareAndConnect()
        }
    }

    private fun prepareAndConnect() {
        val prepareIntent = VpnService.prepare(requireContext())
        if (prepareIntent != null) vpnPermissionLauncher.launch(prepareIntent)
        else startVpn()
    }

    private fun startVpn() {
        val idx = configSpinner.selectedItemPosition
        if (idx < 0 || idx >= configs.size) {
            showSnackbar(getString(R.string.vpn_select_config))
            return
        }
        val config = configs[idx]
        requireContext().startForegroundService(
            Intent(requireContext(), FireTunnelVpnService::class.java).apply {
                action = FireTunnelVpnService.ACTION_CONNECT
                putExtra(FireTunnelVpnService.EXTRA_CONFIG_TOML, config.rawToml)
            }
        )
        updateStatusUI(FireTunnelVpnService.STATE_CONNECTING)
    }

    private fun stopVpn() {
        requireContext().startService(
            Intent(requireContext(), FireTunnelVpnService::class.java).apply {
                action = FireTunnelVpnService.ACTION_DISCONNECT
            }
        )
        updateStatusUI(FireTunnelVpnService.STATE_DISCONNECTED)
    }

    // ── Delete config ──────────────────────────────────────────────────────────

    private fun confirmDeleteConfig() {
        val idx = configSpinner.selectedItemPosition
        if (idx < 0 || idx >= configs.size) return
        val config = configs[idx]
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.delete_config_title)
            .setMessage(getString(R.string.delete_config_message, config.name))
            .setPositiveButton(R.string.delete) { _, _ ->
                configManager.deleteConfig(config.id)
                loadConfigs()
                showSnackbar(getString(R.string.config_deleted, config.name))
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ── Status UI — uses Material You colour roles ─────────────────────────────

    private fun updateStatusUI(state: String) {
        vpnState = state
        val ctx = context ?: return

        when (state) {
            FireTunnelVpnService.STATE_CONNECTED -> {
                statusLabel.text = getString(R.string.status_connected)
                statusText.text  = getString(R.string.connected)
                connectionButton.text = getString(R.string.disconnect)
                val bg   = MaterialColors.getColor(ctx, MaterialR.attr.colorTertiaryContainer, Color.GREEN)
                val fg   = MaterialColors.getColor(ctx, MaterialR.attr.colorOnTertiaryContainer, Color.BLACK)
                statusCard.setCardBackgroundColor(bg)
                statusText.setTextColor(fg)
                statusLabel.setTextColor(fg)
                ImageViewCompat.setImageTintList(statusIcon, ColorStateList.valueOf(fg))
            }
            FireTunnelVpnService.STATE_CONNECTING -> {
                statusLabel.text = getString(R.string.status_connecting)
                statusText.text  = getString(R.string.connecting)
                connectionButton.text = getString(R.string.disconnect)
                val bg   = MaterialColors.getColor(ctx, MaterialR.attr.colorSecondaryContainer, Color.LTGRAY)
                val fg   = MaterialColors.getColor(ctx, MaterialR.attr.colorOnSecondaryContainer, Color.DKGRAY)
                statusCard.setCardBackgroundColor(bg)
                statusText.setTextColor(fg)
                statusLabel.setTextColor(fg)
                ImageViewCompat.setImageTintList(statusIcon, ColorStateList.valueOf(fg))
            }
            FireTunnelVpnService.STATE_ERROR -> {
                statusLabel.text = getString(R.string.status_disconnected)
                statusText.text  = getString(R.string.disconnected)
                connectionButton.text = getString(R.string.connect)
                val bg   = MaterialColors.getColor(ctx, MaterialR.attr.colorErrorContainer, Color.RED)
                val fg   = MaterialColors.getColor(ctx, MaterialR.attr.colorOnErrorContainer, Color.WHITE)
                statusCard.setCardBackgroundColor(bg)
                statusText.setTextColor(fg)
                statusLabel.setTextColor(fg)
                ImageViewCompat.setImageTintList(statusIcon, ColorStateList.valueOf(fg))
                statsText.text = getString(R.string.no_stats)
            }
            else -> { // DISCONNECTED
                statusLabel.text = getString(R.string.status_disconnected)
                statusText.text  = getString(R.string.disconnected)
                connectionButton.text = getString(R.string.connect)
                val bg   = MaterialColors.getColor(ctx, MaterialR.attr.colorSurfaceVariant, Color.LTGRAY)
                val fg   = MaterialColors.getColor(ctx, MaterialR.attr.colorOnSurfaceVariant, Color.DKGRAY)
                statusCard.setCardBackgroundColor(bg)
                statusText.setTextColor(fg)
                statusLabel.setTextColor(fg)
                ImageViewCompat.setImageTintList(statusIcon, ColorStateList.valueOf(fg))
                statsText.text = getString(R.string.no_stats)
            }
        }
    }

    // ── Stats / byte counter ───────────────────────────────────────────────────

    private fun updateStats(json: String) {
        runCatching {
            fun extract(key: String): Long? =
                Regex(""""$key"\s*:\s*(\d+)""").find(json)?.groupValues?.get(1)?.toLong()
            val rx = extract("bytesReceived") ?: extract("rx") ?: extract("received")
            val tx = extract("bytesSent")     ?: extract("tx") ?: extract("sent")
            if (rx != null || tx != null) {
                statsText.text = "↓ ${rx?.let(::formatBytes) ?: "—"}  ↑ ${tx?.let(::formatBytes) ?: "—"}"
            }
        }
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1_024L         -> "$bytes B"
        bytes < 1_048_576L     -> "${"%.1f".format(bytes / 1_024.0)} KB"
        bytes < 1_073_741_824L -> "${"%.1f".format(bytes / 1_048_576.0)} MB"
        else                   -> "${"%.2f".format(bytes / 1_073_741_824.0)} GB"
    }

    private fun showSnackbar(msg: String) {
        view?.let { Snackbar.make(it, msg, Snackbar.LENGTH_SHORT).show() }
    }
}
