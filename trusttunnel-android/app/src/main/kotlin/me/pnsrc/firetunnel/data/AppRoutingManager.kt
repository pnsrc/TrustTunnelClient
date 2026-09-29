package me.pnsrc.firetunnel.data

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable

/** An installed app that can be picked for per-app routing. */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val icon: Drawable,
    val isSystem: Boolean
)

/** Persistent per-app split tunnelling settings. */
class AppRoutingManager(context: Context) {

    companion object {
        private const val PREFS_NAME   = "firetunnel_app_routing"
        private const val KEY_MODE     = "mode"
        private const val KEY_PACKAGES = "packages"
    }

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getMode(): AppRoutingMode = AppRoutingMode.fromName(prefs.getString(KEY_MODE, null))

    fun setMode(mode: AppRoutingMode) {
        prefs.edit().putString(KEY_MODE, mode.name).apply()
    }

    fun getSelectedPackages(): Set<String> =
        prefs.getStringSet(KEY_PACKAGES, emptySet())?.toSet().orEmpty()

    fun setSelectedPackages(packages: Set<String>) {
        prefs.edit().putStringSet(KEY_PACKAGES, packages.toSet()).apply()
    }

    /** Build the plan the VPN service applies to its TUN interface. */
    fun plan(): AppRoutingPlan =
        AppRouting.plan(getMode(), getSelectedPackages(), appContext.packageName)

    /**
     * List launchable apps (blocking — call off the main thread), sorted by label.
     * FireTunnel itself is excluded: it always bypasses the VPN.
     */
    fun loadLaunchableApps(): List<InstalledApp> {
        val pm = appContext.packageManager
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION")
        return pm.queryIntentActivities(launcher, PackageManager.MATCH_ALL)
            .map { it.activityInfo.applicationInfo }
            .distinctBy { it.packageName }
            .filter { it.packageName != appContext.packageName }
            .map { info ->
                InstalledApp(
                    packageName = info.packageName,
                    label = info.loadLabel(pm).toString(),
                    icon = info.loadIcon(pm),
                    isSystem = info.flags and ApplicationInfo.FLAG_SYSTEM != 0
                )
            }
            .sortedBy { it.label.lowercase() }
    }
}
