package me.pnsrc.firetunnel

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.content.res.ColorStateList
import android.graphics.Color
import androidx.core.view.ViewCompat
import com.google.android.material.color.DynamicColors
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import me.pnsrc.firetunnel.data.AppRoutingManager
import me.pnsrc.firetunnel.data.AppRoutingMode
import me.pnsrc.firetunnel.data.AppSettings
import me.pnsrc.firetunnel.data.RoutingRules
import me.pnsrc.firetunnel.data.UpdateManager

/**
 * Settings: every option applies immediately. Only settings that actually do
 * something on Android are offered; the kill switch and always-on VPN are the
 * system's own and are opened from here.
 */
class SettingsActivity : ThemedActivity() {

    private lateinit var settings: AppSettings
    private lateinit var updates: UpdateManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        settings = AppSettings(this)
        updates = UpdateManager(this)

        setupAppearance()
        setupConnection()
        setupNotifications()
        setupDiagnostics()
        setupUpdates()
        setupAbout()
    }

    private fun row(id: Int) = SettingRow(findViewById(id))

    override fun onResume() {
        super.onResume()
        updateBypassRow()
    }

    // ── Appearance ─────────────────────────────────────────────────────────────

    private fun setupAppearance() {
        val modes = AppSettings.THEME_MODES
        val modeLabels = arrayOf<CharSequence>(
            getString(R.string.settings_theme_system), getString(R.string.settings_theme_light),
            getString(R.string.settings_theme_dark)
        )
        val theme = row(R.id.rowTheme).bind(R.drawable.ic_ft_theme, getString(R.string.settings_theme))
        theme.setSubtitle(modeLabels[modes.indexOf(settings.themeMode)])
        theme.asLink {
            MaterialAlertDialogBuilder(this)
                .setTitle(R.string.settings_theme)
                .setSingleChoiceItems(modeLabels, modes.indexOf(settings.themeMode)) { dialog, which ->
                    dialog.dismiss()
                    if (modes[which] == settings.themeMode) return@setSingleChoiceItems
                    settings.themeMode = modes[which]
                    settings.bumpAppearanceVersion()
                    ThemedActivity.applyNightMode(settings) // recreates open screens
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }

        val dynamicAvailable = DynamicColors.isDynamicColorAvailable()
        val dynamic = row(R.id.rowDynamicColor).bind(
            R.drawable.ic_ft_wallpaper, getString(R.string.settings_dynamic_color),
            getString(if (dynamicAvailable) R.string.settings_dynamic_color_sub else R.string.settings_dynamic_color_unsupported)
        )
        val palette = row(R.id.rowPalette).bind(R.drawable.ic_ft_palette, getString(R.string.settings_palette),
            paletteLabel(settings.palette))
        dynamic.asSwitch(settings.dynamicColor && dynamicAvailable) { checked ->
            settings.dynamicColor = checked
            settings.bumpAppearanceVersion()
            recreate()
        }
        dynamic.setEnabled(dynamicAvailable)
        val paletteInUse = !(settings.dynamicColor && dynamicAvailable)
        palette.setEnabled(paletteInUse)
        if (!paletteInUse) palette.setSubtitle(getString(R.string.settings_palette_dynamic))
        palette.asLink { if (paletteInUse) showPalettePicker() }
    }

    private fun paletteLabel(palette: String): String = getString(when (palette) {
        "ocean" -> R.string.palette_ocean
        "forest" -> R.string.palette_forest
        "amethyst" -> R.string.palette_amethyst
        else -> R.string.palette_fire
    })

    private fun paletteColor(palette: String): Int = getColor(when (palette) {
        "ocean" -> R.color.pal_ocean_primary
        "forest" -> R.color.pal_forest_primary
        "amethyst" -> R.color.pal_amethyst_primary
        else -> R.color.fire_primary
    })

    /** Four big swatches; picking one re-themes the app right away. */
    private fun showPalettePicker() {
        val density = resources.displayMetrics.density
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            val pad = (20 * density).toInt()
            setPadding(pad, pad / 2, pad, 0)
        }
        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.settings_palette)
            .setView(row)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        for (palette in AppSettings.PALETTES) {
            val selected = palette == settings.palette
            val item = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                isClickable = true
                isFocusable = true
                setBackgroundResource(android.R.drawable.list_selector_background)
                contentDescription = paletteLabel(palette)
                ViewCompat.setStateDescription(this, if (selected) getString(R.string.state_on) else null)
                setOnClickListener {
                    dialog.dismiss()
                    if (!selected) {
                        settings.palette = palette
                        settings.bumpAppearanceVersion()
                        recreate()
                    }
                }
            }
            val swatchSize = (52 * density).toInt()
            item.addView(ImageView(this).apply {
                layoutParams = LinearLayout.LayoutParams(swatchSize, swatchSize)
                setBackgroundResource(R.drawable.bg_pill)
                backgroundTintList = ColorStateList.valueOf(paletteColor(palette))
                if (selected) {
                    setImageResource(R.drawable.ic_ft_check)
                    val pad = (14 * density).toInt()
                    setPadding(pad, pad, pad, pad)
                    imageTintList = ColorStateList.valueOf(Color.WHITE)
                }
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            })
            item.addView(TextView(this).apply {
                text = paletteLabel(palette)
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
                gravity = Gravity.CENTER
                setPadding(0, (8 * density).toInt(), 0, (8 * density).toInt())
            })
            row.addView(item)
        }
        dialog.show()
    }

    // ── Connection ─────────────────────────────────────────────────────────────

    private fun updateBypassRow() {
        val routing = AppRoutingManager(this)
        val count = routing.getSelectedPackages().size
        val summary = when (routing.getMode()) {
            AppRoutingMode.OFF -> getString(R.string.app_routing_summary_off)
            AppRoutingMode.BYPASS_SELECTED ->
                resources.getQuantityString(R.plurals.app_routing_summary_bypass, count, count)
            AppRoutingMode.ONLY_SELECTED ->
                if (count == 0) getString(R.string.app_routing_summary_only_empty)
                else resources.getQuantityString(R.plurals.app_routing_summary_only, count, count)
        }
        row(R.id.rowBypassApps).setSubtitle(summary)
    }

    private fun setupConnection() {
        row(R.id.rowBypassApps)
            .bind(R.drawable.ic_ft_apps, getString(R.string.settings_bypass_apps))
            .asLink { startActivity(Intent(this, AppRoutingActivity::class.java)) }
        row(R.id.rowAlwaysOn)
            .bind(R.drawable.ic_ft_lock, getString(R.string.settings_always_on), getString(R.string.settings_always_on_sub))
            .asLink { openSystem(Intent(Settings.ACTION_VPN_SETTINGS)) }

    }

    private fun logLevelLabel(level: String?): String = when (level) {
        null -> getString(R.string.settings_log_level_config)
        "debug" -> getString(R.string.settings_log_level_debug)
        "trace" -> getString(R.string.settings_log_level_trace)
        else -> getString(R.string.settings_log_level_info)
    }

    // ── Diagnostics ────────────────────────────────────────────────────────────

    private fun setupDiagnostics() {
        row(R.id.rowLogs)
            .bind(R.drawable.ic_ft_logs, getString(R.string.logs_title), getString(R.string.settings_logs_sub))
            .asLink { startActivity(Intent(this, LogsActivity::class.java)) }

        val logRow = row(R.id.rowLogLevel).bind(R.drawable.ic_ft_terminal, getString(R.string.settings_log_level))
        logRow.setSubtitle(logLevelLabel(settings.logLevelOverride))
        logRow.asLink {
            val values = listOf<String?>(null) + RoutingRules.LOG_LEVELS
            val labels = values.map(::logLevelLabel).toTypedArray()
            MaterialAlertDialogBuilder(this)
                .setTitle(R.string.settings_log_level)
                .setSingleChoiceItems(labels, values.indexOf(settings.logLevelOverride)) { dialog, which ->
                    settings.logLevelOverride = values[which]
                    logRow.setSubtitle(labels[which])
                    dialog.dismiss()
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }


    // ── Notifications ──────────────────────────────────────────────────────────

    private fun setupNotifications() {
        val live = row(R.id.rowLiveUpdates)
        val supported = Build.VERSION.SDK_INT >= LiveUpdates.MIN_SDK
        live.bind(
            R.drawable.ic_ft_live,
            getString(R.string.settings_live_updates),
            getString(if (supported) R.string.settings_live_updates_sub else R.string.settings_live_updates_unsupported)
        ).asSwitch(settings.liveUpdates && supported) { checked -> settings.liveUpdates = checked }
        live.setEnabled(supported)

        row(R.id.rowNotificationSettings)
            .bind(R.drawable.ic_ft_bell, getString(R.string.settings_notification_settings))
            .asLink {
                openSystem(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
            }
    }

    // ── Updates ────────────────────────────────────────────────────────────────

    private fun setupUpdates() {
        row(R.id.rowUpdatesAuto)
            .bind(R.drawable.ic_ft_refresh, getString(R.string.updates_auto), getString(R.string.updates_auto_sub))
            .asSwitch(updates.autoCheckEnabled) { checked -> updates.autoCheckEnabled = checked }

        val check = row(R.id.rowUpdatesCheck)
        val installed = getString(R.string.updates_installed, updates.currentVersionName)
        check.bind(R.drawable.ic_ft_down, getString(R.string.updates_check_now), installed)
        check.asLink {
            check.setSubtitle(getString(R.string.updates_checking))
            check.setEnabled(false)
            UpdateUi.checkNow(this) {
                check.setSubtitle(installed)
                check.setEnabled(true)
            }
        }
    }

    // ── About ──────────────────────────────────────────────────────────────────

    private fun setupAbout() {
        val debug = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        row(R.id.rowAboutApp).bind(
            R.drawable.ic_ft_info,
            getString(R.string.about_app_title, updates.currentVersionName),
            "${if (debug) "debug" else "release"} · $packageName"
        ).asInfo()

        val manufacturer = Build.MANUFACTURER.replaceFirstChar { it.uppercase() }
        val device = if (Build.MODEL.startsWith(manufacturer, ignoreCase = true)) Build.MODEL
                     else "$manufacturer ${Build.MODEL}"
        val details = listOfNotNull(
            "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            Build.SUPPORTED_ABIS.firstOrNull(),
            System.getProperty("os.version")?.let { "Linux $it" }
        ).joinToString(" · ")
        row(R.id.rowAboutDevice).bind(R.drawable.ic_ft_phone, device, details).asInfo()

        row(R.id.rowSource)
            .bind(R.drawable.ic_ft_code, getString(R.string.about_source), "github.com/${UpdateManager.REPO}")
            .asLink { openSystem(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/${UpdateManager.REPO}"))) }
    }

    private fun openSystem(intent: Intent) {
        runCatching { startActivity(intent) }
            .onFailure { startActivity(Intent(Settings.ACTION_SETTINGS)) }
    }
}
