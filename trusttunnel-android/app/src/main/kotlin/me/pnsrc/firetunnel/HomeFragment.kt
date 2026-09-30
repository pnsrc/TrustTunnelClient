package me.pnsrc.firetunnel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.res.ColorStateList
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.material.R as MaterialR
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.CircularProgressIndicator
import com.google.android.material.snackbar.Snackbar
import me.pnsrc.firetunnel.UiKit.Tone
import me.pnsrc.firetunnel.data.ConfigFields
import me.pnsrc.firetunnel.data.ConfigManager
import me.pnsrc.firetunnel.data.EndpointPinger
import me.pnsrc.firetunnel.data.EnrollResult
import me.pnsrc.firetunnel.data.EnrollmentManager
import me.pnsrc.firetunnel.data.StatsFormat
import me.pnsrc.firetunnel.data.VpnConfig
import java.util.concurrent.Executors

/**
 * VPN tab: a big power button inside a status ring, the active server (tap to
 * switch in a bottom sheet) and four session tiles.
 */
class HomeFragment : Fragment() {

    private companion object {
        const val PING_INTERVAL_MS = 30_000L
    }

    /** A statistics tile from `view_stat_tile.xml`. */
    private class StatTile(root: View) {
        val label: TextView = root.findViewById(R.id.statLabel)
        val value: TextView = root.findViewById(R.id.statValue)
    }

    private lateinit var configManager: ConfigManager
    private lateinit var statusChip: TextView
    private lateinit var statusHeadline: TextView
    private lateinit var statusSub: TextView
    private lateinit var statusRing: CircularProgressIndicator
    private lateinit var powerButton: MaterialButton
    private lateinit var serverName: TextView
    private lateinit var serverSub: TextView
    private lateinit var serverPing: TextView
    private lateinit var tileRx: StatTile
    private lateinit var tileTx: StatTile
    private lateinit var tileSpeed: StatTile
    private lateinit var tileConns: StatTile

    private var configs: List<VpnConfig> = emptyList()
    private var active: VpnConfig? = null
    private var vpnState: String = FireTunnelVpnService.STATE_DISCONNECTED
    private var lastError: String? = null

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
    private val pingExecutor = Executors.newFixedThreadPool(3) { r -> Thread(r, "endpoint-ping") }
    private var pingGeneration = 0
    private val pingTicker = object : Runnable {
        override fun run() {
            pingActive()
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
            lastError = intent.getStringExtra(FireTunnelVpnService.EXTRA_ERROR_MSG)
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

        statusChip     = view.findViewById(R.id.statusChip)
        statusHeadline = view.findViewById(R.id.statusHeadline)
        statusSub      = view.findViewById(R.id.statusSub)
        statusRing     = view.findViewById(R.id.statusRing)
        powerButton    = view.findViewById(R.id.powerButton)
        serverName     = view.findViewById(R.id.serverName)
        serverSub      = view.findViewById(R.id.serverSub)
        serverPing     = view.findViewById(R.id.serverPing)
        tileRx    = StatTile(view.findViewById(R.id.statRx))
        tileTx    = StatTile(view.findViewById(R.id.statTx))
        tileSpeed = StatTile(view.findViewById(R.id.statSpeed))
        tileConns = StatTile(view.findViewById(R.id.statConns))

        setupTile(tileRx, R.drawable.ic_ft_down, R.string.stat_rx)
        setupTile(tileTx, R.drawable.ic_ft_up, R.string.stat_tx)
        setupTile(tileSpeed, R.drawable.ic_ft_gauge, R.string.stat_speed)
        setupTile(tileConns, R.drawable.ic_ft_link, R.string.stat_connections)

        powerButton.setOnClickListener { onPowerClicked() }
        view.findViewById<MaterialCardView>(R.id.serverCard).setOnClickListener { onServerClicked() }

        loadConfigs()
        updateStatusUI(FireTunnelVpnService.lastKnownState)
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(FireTunnelVpnService.BROADCAST_STATE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requireContext().registerReceiver(vpnStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
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

    private fun setupTile(tile: StatTile, iconRes: Int, labelRes: Int) {
        tile.label.text = getString(labelRes)
        val icon = ContextCompat.getDrawable(requireContext(), iconRes)?.mutate()
        val size = (16 * resources.displayMetrics.density).toInt()
        icon?.setBounds(0, 0, size, size)
        icon?.setTint(UiKit.themeColor(requireContext(), MaterialR.attr.colorOnSurfaceVariant))
        tile.label.setCompoundDrawablesRelative(icon, null, null, null)
    }

    // ── Configs ────────────────────────────────────────────────────────────────

    private fun loadConfigs() {
        if (view == null) return
        configs = configManager.getConfigs()
        val previousId = active?.id
        active = configManager.getActiveConfig(configs)
        val config = active

        if (config == null) {
            serverName.text = getString(R.string.server_none)
            serverSub.text = getString(R.string.server_none_hint)
            serverPing.visibility = View.GONE
        } else {
            serverName.text = config.name
            serverSub.text = if (EnrollmentManager(requireContext()).isEnrolled(config.id)) {
                getString(R.string.enrolled_badge)
            } else {
                ConfigFields.upstreamProtocol(config.rawToml)
            }
            if (config.id != previousId) pingActive()
        }
        powerButton.isEnabled = config != null
            || vpnState == FireTunnelVpnService.STATE_CONNECTED
            || vpnState == FireTunnelVpnService.STATE_CONNECTING
    }

    private fun onServerClicked() {
        if (configs.isEmpty()) {
            (activity as? MainActivity)?.openConfigs(showAddSheet = true)
        } else {
            showServerSheet()
        }
    }

    /** Bottom sheet listing every config with its ping; tap one to make it active. */
    private fun showServerSheet() {
        val ctx = requireContext()
        val dialog = BottomSheetDialog(ctx)
        val sheet = layoutInflater.inflate(R.layout.sheet_servers, null)
        val rows = sheet.findViewById<LinearLayout>(R.id.serverRows)
        val enrollment = EnrollmentManager(ctx)
        val primary = UiKit.themeColor(ctx, MaterialR.attr.colorPrimary)
        val onPrimary = UiKit.themeColor(ctx, MaterialR.attr.colorOnPrimary)
        val outline = UiKit.themeColor(ctx, MaterialR.attr.colorOutlineVariant)
        val selectedBg = UiKit.themeColor(ctx, MaterialR.attr.colorSurfaceContainerHigh)

        for (config in configs) {
            val row = layoutInflater.inflate(R.layout.item_server_row, rows, false) as MaterialCardView
            val selected = config.id == active?.id
            row.findViewById<TextView>(R.id.serverRowName).text = config.name
            row.findViewById<TextView>(R.id.serverRowSub).text =
                if (enrollment.isEnrolled(config.id)) getString(R.string.enrolled_badge)
                else UiKit.endpointSummary(config)
            val check = row.findViewById<ImageView>(R.id.serverCheck)
            check.setBackgroundResource(R.drawable.bg_pill)
            check.backgroundTintList = ColorStateList.valueOf(if (selected) primary else outline)
            check.imageTintList = ColorStateList.valueOf(onPrimary)
            check.imageAlpha = if (selected) 255 else 0
            row.strokeColor = if (selected) primary else outline
            if (selected) row.setCardBackgroundColor(selectedBg)
            row.contentDescription = config.name
            row.isSelected = selected
            row.setOnClickListener {
                configManager.setActiveConfigId(config.id)
                dialog.dismiss()
                loadConfigs()
                if (vpnState == FireTunnelVpnService.STATE_CONNECTED && config.id != FireTunnelVpnService.activeConfigId) {
                    showSnackbar(getString(R.string.server_reconnect_hint))
                }
            }

            val pingView = row.findViewById<TextView>(R.id.serverRowPing)
            UiKit.stylePill(pingView, Tone.NEUTRAL)
            val target = ConfigFields.firstEndpointAddress(config.rawToml)
            if (target == null) {
                pingView.visibility = View.GONE
            } else {
                runCatching {
                    pingExecutor.execute {
                        val ms = EndpointPinger.ping(target)
                        uiHandler.post { if (dialog.isShowing) UiKit.showPing(pingView, ms) }
                    }
                }
            }
            rows.addView(row)
        }
        sheet.findViewById<MaterialButton>(R.id.serverAdd).setOnClickListener {
            dialog.dismiss()
            (activity as? MainActivity)?.openConfigs(showAddSheet = true)
        }
        dialog.setContentView(sheet)
        dialog.show()
    }

    // ── Connect / disconnect ───────────────────────────────────────────────────

    private fun onPowerClicked() {
        if (vpnState == FireTunnelVpnService.STATE_CONNECTED
            || vpnState == FireTunnelVpnService.STATE_CONNECTING
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
        val config = active
        if (config == null) {
            showSnackbar(getString(R.string.vpn_select_config))
            return
        }
        lastError = null
        if (!EnrollmentManager(requireContext()).isEnrolled(config.id)) {
            launchVpn(config)
            return
        }

        // Enrolled config: re-check the link first so that a revoked device never
        // connects and a changed endpoint is picked up. Failures keep the old config.
        updateStatusUI(FireTunnelVpnService.STATE_CONNECTING)
        powerButton.isEnabled = false
        val appContext = requireContext().applicationContext
        EnrollmentManager.runAsync({ EnrollmentManager(appContext).sync(config.id) }) { outcome ->
            if (!isAdded) return@runAsync
            powerButton.isEnabled = true
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

    // ── Status ─────────────────────────────────────────────────────────────────

    private fun updateStatusUI(state: String) {
        vpnState = state
        val ctx = context ?: return
        if (view == null) return

        val primary = UiKit.themeColor(ctx, MaterialR.attr.colorPrimary)
        val surface = UiKit.themeColor(ctx, MaterialR.attr.colorSurfaceContainerLowest)
        val outline = UiKit.themeColor(ctx, MaterialR.attr.colorOutlineVariant)
        val ok = ContextCompat.getColor(ctx, R.color.status_ok)
        val onOk = ContextCompat.getColor(ctx, R.color.status_on_ok)
        val okContainer = ContextCompat.getColor(ctx, R.color.status_ok_container)
        val host = active?.let { ConfigFields.firstEndpointAddress(it.rawToml)?.host ?: it.name }.orEmpty()

        val chipTone: Tone
        val ringTrack: Int
        var buttonBg = surface
        var buttonFg = primary
        when (state) {
            FireTunnelVpnService.STATE_CONNECTED -> {
                chipTone = Tone.OK
                statusChip.text = getString(R.string.status_chip_on)
                statusHeadline.text = getString(R.string.status_headline_on)
                statusSub.text = getString(R.string.status_sub_on, host)
                powerButton.text = getString(R.string.power_off)
                powerButton.contentDescription = getString(R.string.power_off_desc)
                ringTrack = okContainer
                buttonBg = ok
                buttonFg = onOk
            }
            FireTunnelVpnService.STATE_CONNECTING -> {
                chipTone = Tone.WARN
                statusChip.text = getString(R.string.status_chip_connecting)
                statusHeadline.text = getString(R.string.status_headline_connecting)
                statusSub.text = getString(R.string.status_sub_connecting)
                powerButton.text = getString(R.string.power_cancel)
                powerButton.contentDescription = getString(R.string.power_cancel_desc)
                ringTrack = UiKit.themeColor(ctx, MaterialR.attr.colorPrimaryContainer)
            }
            FireTunnelVpnService.STATE_ERROR -> {
                chipTone = Tone.ERROR
                statusChip.text = getString(R.string.status_chip_error)
                statusHeadline.text = getString(R.string.status_headline_error)
                statusSub.text = lastError ?: getString(R.string.status_sub_error)
                powerButton.text = getString(R.string.power_on)
                powerButton.contentDescription = getString(R.string.power_on_desc)
                ringTrack = UiKit.themeColor(ctx, MaterialR.attr.colorErrorContainer)
            }
            else -> {
                chipTone = Tone.NEUTRAL
                statusChip.text = getString(R.string.status_chip_off)
                statusHeadline.text = getString(R.string.status_headline_off)
                statusSub.text = getString(R.string.status_sub_off)
                powerButton.text = getString(R.string.power_on)
                powerButton.contentDescription = getString(R.string.power_on_desc)
                ringTrack = outline
            }
        }
        UiKit.stylePill(statusChip, chipTone)

        // The ring spins while connecting; otherwise only its track colour shows.
        val connecting = state == FireTunnelVpnService.STATE_CONNECTING
        if (statusRing.isIndeterminate != connecting) {
            statusRing.hide()
            statusRing.isIndeterminate = connecting
            statusRing.progress = 0
            statusRing.show()
        }
        statusRing.trackColor = ringTrack
        statusRing.setIndicatorColor(primary)

        powerButton.backgroundTintList = ColorStateList.valueOf(buttonBg)
        powerButton.setTextColor(buttonFg)
        powerButton.iconTint = ColorStateList.valueOf(buttonFg)
        powerButton.isEnabled = active != null || state != FireTunnelVpnService.STATE_DISCONNECTED
        renderStats()
    }

    // ── Stats / ping ───────────────────────────────────────────────────────────

    private fun renderStats() {
        if (view == null) return
        val ctx = requireContext()
        val stats = FireTunnelVpnService.sessionStats()
        val tiles = listOf(tileRx, tileTx, tileSpeed, tileConns)
        if (stats == null || vpnState != FireTunnelVpnService.STATE_CONNECTED) {
            val dim = UiKit.themeColor(ctx, MaterialR.attr.colorOutline)
            tiles.forEach {
                it.value.text = getString(R.string.no_stats)
                it.value.setTextColor(dim)
            }
            lastRx = -1L
            return
        }
        val onSurface = UiKit.themeColor(ctx, MaterialR.attr.colorOnSurface)
        tiles.forEach { it.value.setTextColor(onSurface) }

        val now = System.currentTimeMillis()
        statusHeadline.text = StatsFormat.uptime((now - stats.connectedAt) / 1000)
        val rx = stats.rxBytes
        val tx = stats.txBytes
        tileRx.value.text = rx?.let(StatsFormat::bytes) ?: getString(R.string.no_stats)
        tileTx.value.text = tx?.let(StatsFormat::bytes) ?: getString(R.string.no_stats)
        if (rx != null && tx != null) {
            if (lastRx >= 0 && now > lastSampleAt) {
                val seconds = (now - lastSampleAt) / 1000.0
                val total = ((rx - lastRx) + (tx - lastTx)) / seconds
                tileSpeed.value.text = StatsFormat.speed(total.toLong().coerceAtLeast(0))
            }
            lastRx = rx
            lastTx = tx
            lastSampleAt = now
        } else {
            tileSpeed.value.text = getString(R.string.no_stats)
        }
        tileConns.value.text = getString(R.string.stat_connections_value, stats.tunnelConnections, stats.bypassConnections)
    }

    /** Ping the active config's first endpoint address in the background. */
    private fun pingActive() {
        if (view == null) return
        val target = active?.let { ConfigFields.firstEndpointAddress(it.rawToml) }
        val generation = ++pingGeneration
        if (target == null) {
            serverPing.visibility = View.GONE
            return
        }
        if (serverPing.visibility != View.VISIBLE) {
            serverPing.visibility = View.VISIBLE
            serverPing.text = getString(R.string.ping_short_measuring)
            UiKit.stylePill(serverPing, Tone.NEUTRAL)
        }
        runCatching {
            pingExecutor.execute {
                val ms = EndpointPinger.ping(target)
                uiHandler.post {
                    // Drop results for a config that is no longer active.
                    if (view == null || generation != pingGeneration) return@post
                    UiKit.showPing(serverPing, ms)
                }
            }
        }
    }

    private fun showSnackbar(msg: String) {
        view?.let { Snackbar.make(it, msg, Snackbar.LENGTH_SHORT).show() }
    }
}
