package me.pnsrc.firetunnel.data

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build

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
     * List every app that may use the network (requests INTERNET), sorted by label.
     * Blocking — call off the main thread. An app counts as "system" only if it is
     * preinstalled and has no launcher icon (so a preinstalled browser is a normal
     * app). FireTunnel itself is left out: it always bypasses the VPN.
     */
    fun loadNetworkApps(): List<AppEntry> {
        val pm = appContext.packageManager
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION")
        val launchable = pm.queryIntentActivities(launcher, PackageManager.MATCH_ALL)
            .mapTo(HashSet()) { it.activityInfo.packageName }
        @Suppress("DEPRECATION")
        val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }
        return packages
            .filter { it.packageName != appContext.packageName }
            .filter { it.requestedPermissions?.contains(Manifest.permission.INTERNET) == true }
            .mapNotNull { pkg ->
                val info = pkg.applicationInfo ?: return@mapNotNull null
                AppEntry(
                    packageName = pkg.packageName,
                    label = info.loadLabel(pm).toString(),
                    isSystem = info.flags and ApplicationInfo.FLAG_SYSTEM != 0 && pkg.packageName !in launchable
                )
            }
            .sortedBy { it.label.lowercase() }
    }

    /** Load one app's icon (blocking); `null` if it was uninstalled meanwhile. */
    fun loadIcon(packageName: String): Drawable? =
        runCatching { appContext.packageManager.getApplicationIcon(packageName) }.getOrNull()
}
