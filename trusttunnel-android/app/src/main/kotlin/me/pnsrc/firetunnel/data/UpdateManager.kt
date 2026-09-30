package me.pnsrc.firetunnel.data

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.util.Log
import androidx.core.content.FileProvider
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

private const val TAG = "UpdateManager"

/** Result of asking GitHub for a newer release. */
sealed class UpdateCheck {
    data class Available(val release: ReleaseInfo) : UpdateCheck()
    data object UpToDate : UpdateCheck()
    data class Failed(val reason: String) : UpdateCheck()
}

/**
 * In-app updates from GitHub releases: finds the newest release carrying an APK,
 * downloads it into the cache (verifying the SHA-256 GitHub reports and the
 * package name) and hands it to the system installer. Android itself refuses an
 * APK signed with a different key, so only builds signed with the release key
 * can update each other. Network methods block — call them off the main thread.
 */
class UpdateManager(context: Context) {

    companion object {
        const val REPO = "pnsrc/TrustTunnelClient"
        private const val RELEASES_API = "https://api.github.com/repos/$REPO/releases?per_page=15"
        /** Automatic checks run at most daily (the API allows 60 anonymous calls per hour). */
        const val AUTO_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000L
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 30_000
        private const val UPDATES_DIR = "updates"

        private const val PREFS = "firetunnel_updates"
        private const val KEY_LAST_CHECK = "last_check"
        private const val KEY_SKIPPED = "skipped_tag"
        private const val KEY_AUTO = "auto_check"
    }

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    // ── Settings ────────────────────────────────────────────────────────────────

    var autoCheckEnabled: Boolean
        get() = prefs.getBoolean(KEY_AUTO, true)
        set(value) = prefs.edit().putBoolean(KEY_AUTO, value).apply()

    val currentVersionName: String
        get() = runCatching {
            appContext.packageManager.getPackageInfo(appContext.packageName, 0).versionName
        }.getOrNull().orEmpty()

    /** Development builds are not signed with the release key and cannot be updated in place. */
    val isDebugBuild: Boolean
        get() = appContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    fun isAutoCheckDue(): Boolean =
        autoCheckEnabled && !isDebugBuild
            && System.currentTimeMillis() - prefs.getLong(KEY_LAST_CHECK, 0L) >= AUTO_CHECK_INTERVAL_MS

    fun skip(release: ReleaseInfo) {
        prefs.edit().putString(KEY_SKIPPED, release.tag).apply()
    }

    fun isSkipped(release: ReleaseInfo): Boolean = prefs.getString(KEY_SKIPPED, null) == release.tag

    // ── Check ───────────────────────────────────────────────────────────────────

    fun check(): UpdateCheck {
        prefs.edit().putLong(KEY_LAST_CHECK, System.currentTimeMillis()).apply()
        return try {
            val json = httpGet(RELEASES_API)
            val release = ReleaseParser.newestUpdate(json, AppVersion.parse(currentVersionName))
            if (release != null) UpdateCheck.Available(release) else UpdateCheck.UpToDate
        } catch (e: IOException) {
            Log.w(TAG, "Update check failed: ${e.javaClass.simpleName}")
            UpdateCheck.Failed(e.message ?: e.javaClass.simpleName)
        }
    }

    // ── Download ────────────────────────────────────────────────────────────────

    /**
     * Download [release]'s APK, reporting `(done, total)` bytes (`total` is -1 if
     * unknown). Throw [IOException] on network errors, cancellation or a failed
     * integrity check; a partial file is never left behind.
     */
    fun download(release: ReleaseInfo, isCancelled: () -> Boolean, onProgress: (Long, Long) -> Unit): File {
        val dir = File(appContext.cacheDir, UPDATES_DIR).apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() } // keep only one update around
        val safeName = release.apkName.replace(Regex("[^A-Za-z0-9._-]"), "_")
        val target = File(dir, safeName)
        val part = File(dir, "$safeName.part")

        val conn = open(release.apkUrl)
        try {
            if (conn.responseCode !in 200..299) throw IOException("HTTP ${conn.responseCode}")
            val total = conn.contentLengthLong.takeIf { it > 0 } ?: release.apkSize
            val digest = MessageDigest.getInstance("SHA-256")
            var done = 0L
            conn.inputStream.use { input ->
                part.outputStream().use { output ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        if (isCancelled()) throw IOException("cancelled")
                        val n = input.read(buf)
                        if (n < 0) break
                        output.write(buf, 0, n)
                        digest.update(buf, 0, n)
                        done += n
                        onProgress(done, total)
                    }
                }
            }
            if (release.apkSize > 0 && done != release.apkSize) throw IOException("size mismatch")
            val sha = digest.digest().joinToString("") { "%02x".format(it) }
            if (release.apkSha256 != null && sha != release.apkSha256) throw IOException("checksum mismatch")
            verifyPackage(part)
            if (!part.renameTo(target)) throw IOException("rename failed")
            return target
        } catch (e: IOException) {
            part.delete()
            throw e
        } finally {
            conn.disconnect()
        }
    }

    /** Refuse an APK that is not FireTunnel (e.g. a wrong asset attached to the release). */
    private fun verifyPackage(apk: File) {
        @Suppress("DEPRECATION")
        val info = appContext.packageManager.getPackageArchiveInfo(apk.path, 0)
            ?: throw IOException("not an APK")
        if (info.packageName != appContext.packageName) throw IOException("wrong package")
    }

    // ── Install ─────────────────────────────────────────────────────────────────

    /** Whether the user allowed FireTunnel to install apps (Android 8+ per-app switch). */
    fun canInstall(): Boolean = appContext.packageManager.canRequestPackageInstalls()

    /** Intent that opens the "Install unknown apps" switch for FireTunnel. */
    fun installPermissionIntent(): Intent =
        Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
            .setData(Uri.parse("package:${appContext.packageName}"))

    /** Intent that hands the downloaded [apk] to the system installer. */
    fun installIntent(apk: File): Intent {
        val uri = FileProvider.getUriForFile(appContext, "${appContext.packageName}.updates", apk)
        return Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    // ── HTTP ────────────────────────────────────────────────────────────────────

    private fun httpGet(url: String): String {
        val conn = open(url)
        try {
            if (conn.responseCode !in 200..299) throw IOException("HTTP ${conn.responseCode}")
            return conn.inputStream.bufferedReader().use { it.readText() }
        } finally {
            conn.disconnect()
        }
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = true // release assets redirect to GitHub's CDN
            setRequestProperty("Accept", "application/vnd.github+json")
            setRequestProperty("User-Agent", "FireTunnel-Android/$currentVersionName")
        }
}
