package me.pnsrc.firetunnel

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import me.pnsrc.firetunnel.data.AppSettings
import me.pnsrc.firetunnel.data.RoutingRules
import me.pnsrc.firetunnel.data.UpdateManager

/**
 * Settings: every option applies immediately. Only settings that actually do
 * something on Android are offered; the kill switch and always-on VPN are the
 * system's own and are opened from here.
 */
class SettingsActivity : AppCompatActivity() {

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

        setupConnection()
        setupNotifications()
        setupUpdates()
        setupAbout()
    }

    private fun row(id: Int) = SettingRow(findViewById(id))

    // ── Connection ─────────────────────────────────────────────────────────────

    private fun setupConnection() {
        row(R.id.rowAlwaysOn)
            .bind(R.drawable.ic_ft_lock, getString(R.string.settings_always_on), getString(R.string.settings_always_on_sub))
            .asLink { openSystem(Intent(Settings.ACTION_VPN_SETTINGS)) }

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

    private fun logLevelLabel(level: String?): String = when (level) {
        null -> getString(R.string.settings_log_level_config)
        "debug" -> getString(R.string.settings_log_level_debug)
        "trace" -> getString(R.string.settings_log_level_trace)
        else -> getString(R.string.settings_log_level_info)
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
