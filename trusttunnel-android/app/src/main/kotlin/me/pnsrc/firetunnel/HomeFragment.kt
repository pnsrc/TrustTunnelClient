package me.pnsrc.firetunnel

import android.animation.ValueAnimator
import android.annotation.SuppressLint
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
import android.view.HapticFeedbackConstants
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.animation.LinearInterpolator
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.widget.ImageViewCompat
import androidx.dynamicanimation.animation.DynamicAnimation
import androidx.dynamicanimation.animation.SpringAnimation
import androidx.dynamicanimation.animation.SpringForce
import androidx.fragment.app.Fragment
import com.google.android.material.R as MaterialR
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.snackbar.Snackbar
import me.pnsrc.firetunnel.UiKit.Tone
import me.pnsrc.firetunnel.data.AppRoutingManager
import me.pnsrc.firetunnel.data.AppRoutingMode
import me.pnsrc.firetunnel.data.AppSettings
import me.pnsrc.firetunnel.data.ConfigFields
import me.pnsrc.firetunnel.data.ConfigManager
import me.pnsrc.firetunnel.data.EndpointPinger
import me.pnsrc.firetunnel.data.EnrollResult
import me.pnsrc.firetunnel.data.EnrollmentManager
import me.pnsrc.firetunnel.data.RoutingRules
import me.pnsrc.firetunnel.data.RulesManager
import me.pnsrc.firetunnel.data.StatsFormat
import me.pnsrc.firetunnel.data.VpnConfig
import java.util.concurrent.Executors

/**
 * VPN tab (Material 3 Expressive): a power button that morphs between shapes
 * on a turning halo, the active server (tap to switch in a bottom sheet), apps
 * that bypass the VPN, a live speed chart and session totals.
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
    private lateinit var powerButton: View
    private lateinit var powerIcon: ImageView
    private lateinit var powerLabel: TextView
    private lateinit var haloShape: MorphShapeDrawable
    private lateinit var buttonShape: MorphShapeDrawable
    private var haloSpin: ValueAnimator? = null
    private var haloSpinDuration = 0L
    private lateinit var speedChart: SpeedChartView
    private lateinit var speedDown: TextView
    private lateinit var speedUp: TextView
    private lateinit var serverName: TextView
    private lateinit var serverSub: TextView
    private lateinit var serverPing: TextView
    private lateinit var tileRx: StatTile
    private lateinit var tileTx: StatTile
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
        powerButton    = view.findViewById(R.id.powerButton)
        powerIcon      = view.findViewById(R.id.powerIcon)
        powerLabel     = view.findViewById(R.id.powerLabel)
        speedChart     = view.findViewById(R.id.speedChart)
        speedDown      = view.findViewById(R.id.speedDown)
        speedUp        = view.findViewById(R.id.speedUp)
        serverName     = view.findViewById(R.id.serverName)
        serverSub      = view.findViewById(R.id.serverSub)
        serverPing     = view.findViewById(R.id.serverPing)
        tileRx    = StatTile(view.findViewById(R.id.statRx))
        tileTx    = StatTile(view.findViewById(R.id.statTx))
        tileConns = StatTile(view.findViewById(R.id.statConns))

        setupTile(tileRx, R.drawable.ic_ft_down, R.string.stat_rx)
        setupTile(tileTx, R.drawable.ic_ft_up, R.string.stat_tx)
        setupTile(tileConns, R.drawable.ic_ft_link, R.string.stat_connections)

        setupPowerButton(view)
        tintCompound(speedDown, androidx.appcompat.R.attr.colorPrimary)
        tintCompound(speedUp, MaterialR.attr.colorTertiary)
        view.findViewById<MaterialCardView>(R.id.serverCard).setOnClickListener { onServerClicked() }
        view.findViewById<MaterialCardView>(R.id.bypassCard).setOnClickListener {
            startActivity(Intent(requireContext(), AppRoutingActivity::class.java))
        }
        serverPing.setOnClickListener { pingActive() }

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
        updateBypassCard()
        updateStatusUI(FireTunnelVpnService.lastKnownState)
        uiHandler.post(statsTicker)
        uiHandler.post(pingTicker)
    }

    override fun onPause() {
        super.onPause()
        runCatching { requireContext().unregisterReceiver(vpnStateReceiver) }
        uiHandler.removeCallbacks(statsTicker)
        uiHandler.removeCallbacks(pingTicker)
        spinHalo(0L)
    }

    override fun onDestroy() {
        super.onDestroy()
        pingExecutor.shutdownNow()
    }

    /** Morphing button on a halo; springs down under the finger, haptic tick on toggle. */
    @SuppressLint("ClickableViewAccessibility")
    private fun setupPowerButton(root: View) {
        val ctx = requireContext()
        haloShape = MorphShapeDrawable(ExpressiveShapes.COOKIE_12,
            UiKit.themeColor(ctx, MaterialR.attr.colorSurfaceContainerHigh))
        buttonShape = MorphShapeDrawable(ExpressiveShapes.COOKIE_9,
            UiKit.themeColor(ctx, MaterialR.attr.colorPrimaryContainer))
        root.findViewById<View>(R.id.powerHalo).background = haloShape
        powerButton.background = buttonShape

        val scaleX = SpringAnimation(powerButton, DynamicAnimation.SCALE_X)
        val scaleY = SpringAnimation(powerButton, DynamicAnimation.SCALE_Y)
        fun springTo(value: Float) {
            for (anim in listOf(scaleX, scaleY)) {
                anim.spring = SpringForce(value)
                    .setStiffness(SpringForce.STIFFNESS_MEDIUM)
                    .setDampingRatio(SpringForce.DAMPING_RATIO_MEDIUM_BOUNCY)
                anim.start()
            }
        }
        powerButton.setOnTouchListener { _, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> springTo(0.9f)
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> springTo(1f)
            }
            false
        }
        powerButton.setOnClickListener {
            it.performHapticFeedback(
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) HapticFeedbackConstants.CONFIRM
                else HapticFeedbackConstants.VIRTUAL_KEY
            )
            onPowerClicked()
        }
    }

    /** Turn the halo: fast while connecting, slowly while connected, still otherwise. */
    private fun spinHalo(durationMs: Long) {
        if (durationMs == haloSpinDuration && haloSpin?.isRunning == true) return
        haloSpin?.cancel()
        haloSpin = null
        haloSpinDuration = durationMs
        if (durationMs <= 0L) return
        val from = haloShape.rotation
        haloSpin = ValueAnimator.ofFloat(from, from + 360f).apply {
            duration = durationMs
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
            addUpdateListener { haloShape.rotation = (it.animatedValue as Float) % 360f }
            start()
        }
    }

    private fun tintCompound(view: TextView, attr: Int) {
        androidx.core.widget.TextViewCompat.setCompoundDrawableTintList(
            view, ColorStateList.valueOf(UiKit.themeColor(requireContext(), attr))
        )
    }

    /** Show which apps skip the VPN (icons of up to four), or that all apps use it. */
    private fun updateBypassCard() {
        val root = view ?: return
        val ctx = requireContext()
        val routing = AppRoutingManager(ctx)
        val mode = routing.getMode()
        val selected = routing.getSelectedPackages().sorted()
        val pm = ctx.packageManager
        val installed = selected.filter { runCatching { pm.getApplicationInfo(it, 0) }.isSuccess }
        val labels = installed.map { pkg -> runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg) }

        val title = root.findViewById<TextView>(R.id.bypassTitle)
        val sub = root.findViewById<TextView>(R.id.bypassSub)
        val icons = root.findViewById<LinearLayout>(R.id.bypassIcons)
        icons.removeAllViews()
        val size = (32 * resources.displayMetrics.density).toInt()
        val overlap = (-10 * resources.displayMetrics.density).toInt()

        val showApps = mode != AppRoutingMode.OFF && installed.isNotEmpty()
        if (showApps) {
            installed.take(4).forEachIndexed { i, pkg ->
                icons.addView(ImageView(ctx).apply {
                    setImageDrawable(runCatching { pm.getApplicationIcon(pkg) }.getOrNull())
                    importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                    layoutParams = LinearLayout.LayoutParams(size, size).apply { if (i > 0) marginStart = overlap }
                })
            }
            val count = installed.size
            title.text = if (mode == AppRoutingMode.BYPASS_SELECTED)
                resources.getQuantityString(R.plurals.app_routing_summary_bypass, count, count)
                else resources.getQuantityString(R.plurals.app_routing_summary_only, count, count)
            sub.text = labels.take(3).joinToString(", ") + if (count > 3) "…" else ""
        } else {
            icons.addView(ImageView(ctx).apply {
                setImageResource(R.drawable.ic_ft_apps)
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                setBackgroundResource(R.drawable.bg_rounded_14)
                backgroundTintList = ColorStateList.valueOf(UiKit.themeColor(ctx, MaterialR.attr.colorSecondaryContainer))
                ImageViewCompat.setImageTintList(this,
                    ColorStateList.valueOf(UiKit.themeColor(ctx, MaterialR.attr.colorOnSecondaryContainer)))
                val pad = (10 * resources.displayMetrics.density).toInt()
                setPadding(pad, pad, pad, pad)
                layoutParams = LinearLayout.LayoutParams(size + 12, size + 12)
            })
            title.text = getString(R.string.app_routing_summary_off)
            sub.text = getString(R.string.home_bypass_hint)
        }
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
        val primary = UiKit.themeColor(ctx, androidx.appcompat.R.attr.colorPrimary)
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
        // The Rules tab's site list and the Settings log level are applied on top
        // of the stored config for this connection only.
        val ctx = requireContext()
        val toml = RoutingRules.apply(config.rawToml, RulesManager(ctx).overrides(AppSettings(ctx).logLevelOverride))
        ctx.startForegroundService(
            Intent(ctx, FireTunnelVpnService::class.java).apply {
                action = FireTunnelVpnService.ACTION_CONNECT
                putExtra(FireTunnelVpnService.EXTRA_CONFIG_TOML, toml)
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

        fun c(attr: Int) = UiKit.themeColor(ctx, attr)
        val host = active?.let { ConfigFields.firstEndpointAddress(it.rawToml)?.host ?: it.name }.orEmpty()

        val chipTone: Tone
        var buttonBg = c(MaterialR.attr.colorPrimaryContainer)
        var buttonFg = c(MaterialR.attr.colorOnPrimaryContainer)
        var haloBg = c(MaterialR.attr.colorSurfaceContainerHigh)
        val buttonShapeTarget: androidx.graphics.shapes.RoundedPolygon
        val haloShapeTarget: androidx.graphics.shapes.RoundedPolygon
        val spin: Long
        when (state) {
            FireTunnelVpnService.STATE_CONNECTED -> {
                chipTone = Tone.OK
                statusChip.text = getString(R.string.status_chip_on)
                statusHeadline.text = getString(R.string.status_headline_on)
                statusSub.text = getString(R.string.status_sub_on, host)
                powerLabel.text = getString(R.string.power_off)
                powerButton.contentDescription = getString(R.string.power_off_desc)
                buttonBg = ContextCompat.getColor(ctx, R.color.status_ok)
                buttonFg = ContextCompat.getColor(ctx, R.color.status_on_ok)
                haloBg = ContextCompat.getColor(ctx, R.color.status_ok_container)
                buttonShapeTarget = ExpressiveShapes.SUNNY
                haloShapeTarget = ExpressiveShapes.COOKIE_12
                spin = 24_000L
            }
            FireTunnelVpnService.STATE_CONNECTING -> {
                chipTone = Tone.WARN
                statusChip.text = getString(R.string.status_chip_connecting)
                statusHeadline.text = getString(R.string.status_headline_connecting)
                statusSub.text = getString(R.string.status_sub_connecting)
                powerLabel.text = getString(R.string.power_cancel)
                powerButton.contentDescription = getString(R.string.power_cancel_desc)
                haloBg = c(MaterialR.attr.colorSecondaryContainer)
                buttonShapeTarget = ExpressiveShapes.BURST
                haloShapeTarget = ExpressiveShapes.SUNNY
                spin = 2_400L
            }
            FireTunnelVpnService.STATE_ERROR -> {
                chipTone = Tone.ERROR
                statusChip.text = getString(R.string.status_chip_error)
                statusHeadline.text = getString(R.string.status_headline_error)
                statusSub.text = lastError ?: getString(R.string.status_sub_error)
                powerLabel.text = getString(R.string.power_on)
                powerButton.contentDescription = getString(R.string.power_on_desc)
                buttonBg = c(MaterialR.attr.colorErrorContainer)
                buttonFg = c(MaterialR.attr.colorOnErrorContainer)
                buttonShapeTarget = ExpressiveShapes.COOKIE_9
                haloShapeTarget = ExpressiveShapes.COOKIE_12
                spin = 0L
            }
            else -> {
                chipTone = Tone.NEUTRAL
                statusChip.text = getString(R.string.status_chip_off)
                statusHeadline.text = getString(R.string.status_headline_off)
                statusSub.text = getString(R.string.status_sub_off)
                powerLabel.text = getString(R.string.power_on)
                powerButton.contentDescription = getString(R.string.power_on_desc)
                buttonShapeTarget = ExpressiveShapes.COOKIE_9
                haloShapeTarget = ExpressiveShapes.COOKIE_12
                spin = 0L
            }
        }
        UiKit.stylePill(statusChip, chipTone)
        buttonShape.morphTo(buttonShapeTarget)
        buttonShape.setColor(buttonBg)
        haloShape.morphTo(haloShapeTarget)
        haloShape.setColor(haloBg)
        ImageViewCompat.setImageTintList(powerIcon, ColorStateList.valueOf(buttonFg))
        powerLabel.setTextColor(buttonFg)
        spinHalo(if (isResumed) spin else 0L)
        powerButton.isEnabled = active != null || state != FireTunnelVpnService.STATE_DISCONNECTED
        powerButton.alpha = if (powerButton.isEnabled) 1f else 0.5f
        renderStats()
    }

    // ── Stats / ping ───────────────────────────────────────────────────────────

    private fun renderStats() {
        if (view == null) return
        val ctx = requireContext()
        val stats = FireTunnelVpnService.sessionStats()
        val tiles = listOf(tileRx, tileTx, tileConns)
        if (stats == null || vpnState != FireTunnelVpnService.STATE_CONNECTED) {
            val dim = UiKit.themeColor(ctx, MaterialR.attr.colorOutline)
            tiles.forEach {
                it.value.text = getString(R.string.no_stats)
                it.value.setTextColor(dim)
            }
            speedDown.text = getString(R.string.no_stats)
            speedUp.text = getString(R.string.no_stats)
            if (lastRx >= 0) speedChart.clear()
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
                val downBps = ((rx - lastRx) / seconds).toLong().coerceAtLeast(0)
                val upBps = ((tx - lastTx) / seconds).toLong().coerceAtLeast(0)
                speedDown.text = StatsFormat.speed(downBps)
                speedUp.text = StatsFormat.speed(upBps)
                speedChart.push(downBps, upBps)
            }
            lastRx = rx
            lastTx = tx
            lastSampleAt = now
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
