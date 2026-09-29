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
import android.widget.AdapterView
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
import me.pnsrc.firetunnel.data.ConfigFields
import me.pnsrc.firetunnel.data.ConfigManager
import me.pnsrc.firetunnel.data.EndpointPinger
import me.pnsrc.firetunnel.data.StatsFormat
import me.pnsrc.firetunnel.data.EnrollResult
import me.pnsrc.firetunnel.data.EnrollmentManager
import me.pnsrc.firetunnel.data.VpnConfig
import java.util.concurrent.Executors

class HomeFragment : Fragment() {

    private companion object {
        const val PING_INTERVAL_MS = 30_000L
    }

    private lateinit var configManager: ConfigManager
    private lateinit var statusCard: MaterialCardView
    private lateinit var statusIcon: ImageView
    private lateinit var statusLabel: TextView
    private lateinit var statusText: TextView
    private lateinit var connectionButton: MaterialButton
    private lateinit var configSpinner: Spinner
    private lateinit var statsText: TextView
    private lateinit var pingText: TextView
    private lateinit var deleteConfigButton: MaterialButton

    private var configs: List<VpnConfig> = emptyList()
    private var vpnState: String = FireTunnelVpnService.STATE_DISCONNECTED

    // Session stats: refreshed once a second while the screen is visible.
    private val uiHandler = Handler(Looper.getMainLooper())
    private var lastRx = -1L
    private var lastTx = -1L
    private var lastSampleAt = 0L
    private val statsTicker = object : Runnable {
        override fun run() {
            renderStats()
            uiHandler.postDelayed(this, 1_000)
        }
    }

    // Endpoint ping: refreshed every 30 s and whenever another config is selected.
    private val pingExecutor = Executors.newSingleThreadExecutor { r -> Thread(r, "endpoint-ping") }
    private var pingGeneration = 0
    private val pingTicker = object : Runnable {
        override fun run() {
            pingSelected()
            uiHandler.postDelayed(this, PING_INTERVAL_MS)
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

            updateStatusUI(state)
            renderStats()
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
        pingText          = view.findViewById(R.id.pingText)
        deleteConfigButton = view.findViewById(R.id.deleteConfigButton)

        connectionButton.setOnClickListener { onConnectClicked() }
        deleteConfigButton.setOnClickListener { confirmDeleteConfig() }
        configSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, v: View?, position: Int, id: Long) {
                pingSelected()
            }
            override fun onNothingSelected(parent: AdapterView<*>?) = Unit
        }

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
        updateStatusUI(FireTunnelVpnService.lastKnownState)
        uiHandler.post(statsTicker)
        uiHandler.post(pingTicker)
    }

    override fun onPause() {
        super.onPause()
        runCatching { requireContext().unregisterReceiver(vpnStateReceiver) }
        uiHandler.removeCallbacks(statsTicker)
        uiHandler.removeCallbacks(pingTicker)
    }

    override fun onDestroy() {
        super.onDestroy()
        pingExecutor.shutdownNow()
    }

    // ── Config loading ─────────────────────────────────────────────────────────

    private fun loadConfigs() {
        if (!isAdded) return
        val selectedId = configs.getOrNull(configSpinner.selectedItemPosition)?.id
        configs = configManager.getConfigs()
        val names = if (configs.isEmpty()) listOf(getString(R.string.no_configs))
                    else configs.map { it.name }
        val adapter = ArrayAdapter(requireContext(), android.R.layout.simple_spinner_item, names)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        configSpinner.adapter = adapter
        val restored = configs.indexOfFirst { it.id == selectedId }
        if (restored >= 0) configSpinner.setSelection(restored)
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
        if (!EnrollmentManager(requireContext()).isEnrolled(config.id)) {
            launchVpn(config)
            return
        }

        // Enrolled config: re-check the link first so that a revoked device never
        // connects and a changed endpoint is picked up. Failures keep the old config.
        connectionButton.isEnabled = false
        updateStatusUI(FireTunnelVpnService.STATE_CONNECTING)
        val appContext = requireContext().applicationContext
        EnrollmentManager.runAsync({ EnrollmentManager(appContext).sync(config.id) }) { outcome ->
            if (!isAdded) return@runAsync
            loadConfigs()
            if (outcome?.result is EnrollResult.Revoked) {
                updateStatusUI(FireTunnelVpnService.STATE_DISCONNECTED)
                EnrollmentUi.showSyncOutcomes(requireActivity(), listOf(outcome))
                return@runAsync
            }
            launchVpn(configs.firstOrNull { it.id == config.id } ?: config)
        }
    }

    private fun launchVpn(config: VpnConfig) {
        requireContext().startForegroundService(
            Intent(requireContext(), FireTunnelVpnService::class.java).apply {
                action = FireTunnelVpnService.ACTION_CONNECT
                putExtra(FireTunnelVpnService.EXTRA_CONFIG_TOML, config.rawToml)
                putExtra(FireTunnelVpnService.EXTRA_CONFIG_ID, config.id)
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
                EnrollmentManager(requireContext()).forget(config.id)
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

    // ── Stats / ping ───────────────────────────────────────────────────────────

    private fun renderStats() {
        if (view == null) return
        val stats = FireTunnelVpnService.sessionStats()
        if (stats == null || vpnState != FireTunnelVpnService.STATE_CONNECTED) {
            statsText.text = getString(R.string.no_stats)
            lastRx = -1L
            return
        }
        val now = System.currentTimeMillis()
        val lines = mutableListOf(
            getString(R.string.uptime_label, StatsFormat.uptime((now - stats.connectedAt) / 1000))
        )
        val rx = stats.rxBytes
        val tx = stats.txBytes
        if (rx != null && tx != null) {
            lines += getString(R.string.stats_traffic, StatsFormat.bytes(rx), StatsFormat.bytes(tx))
            if (lastRx >= 0 && now > lastSampleAt) {
                val seconds = (now - lastSampleAt) / 1000.0
                lines += getString(
                    R.string.stats_speed,
                    StatsFormat.speed(((rx - lastRx) / seconds).toLong().coerceAtLeast(0)),
                    StatsFormat.speed(((tx - lastTx) / seconds).toLong().coerceAtLeast(0))
                )
            }
            lastRx = rx
            lastTx = tx
            lastSampleAt = now
        }
        lines += getString(R.string.stats_connections, stats.tunnelConnections, stats.bypassConnections)
        statsText.text = lines.joinToString("\n")
    }

    /** Ping the selected config's first endpoint address in the background. */
    private fun pingSelected() {
        if (view == null) return
        val config = configs.getOrNull(configSpinner.selectedItemPosition)
        val target = config?.let { ConfigFields.firstEndpointAddress(it.rawToml) }
        val generation = ++pingGeneration
        if (target == null) {
            pingText.visibility = View.GONE
            return
        }
        pingText.visibility = View.VISIBLE
        if (pingText.text.isNullOrEmpty()) pingText.text = getString(R.string.ping_measuring)
        runCatching {
            pingExecutor.execute {
                val ms = EndpointPinger.ping(target)
                uiHandler.post {
                    // Drop results for a config that is no longer selected.
                    if (view == null || generation != pingGeneration) return@post
                    pingText.text = if (ms != null) getString(R.string.ping_ms, ms)
                                    else getString(R.string.ping_unreachable)
                }
            }
        }
    }

    private fun showSnackbar(msg: String) {
        view?.let { Snackbar.make(it, msg, Snackbar.LENGTH_SHORT).show() }
    }
}
