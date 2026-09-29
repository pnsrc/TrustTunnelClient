package me.pnsrc.firetunnel.data

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import me.pnsrc.firetunnel.FireTunnelVpnService
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import java.util.concurrent.Executors

private const val TAG = "EnrollmentManager"

/** Result of enrolling or syncing one enrollment link. */
data class EnrollOutcome(
    val configId: String,
    val configName: String,
    val result: EnrollResult,
    /** True if the stored config was replaced with a different one or removed. */
    val changed: Boolean = false
)

/**
 * Device enrollment by a dashboard link (`firetunnel://enroll?url=…`).
 *
 * The same `POST <link> {fingerprint, name}` is used both for the first enrollment
 * and for the check on every start: 200 refreshes the stored config, 403/404 wipe it
 * and stop the VPN if it runs with that config, anything else keeps the old config.
 *
 * The link is a secret: it lives in [EncryptedSharedPreferences] and is never logged.
 * All network methods block — call them through [runAsync].
 */
class EnrollmentManager(context: Context) {

    companion object {
        /** Server limit is 30 req/min per address; one automatic sync per link per minute. */
        const val MIN_SYNC_INTERVAL_MS = 60_000L

        private const val PREFS_NAME       = "firetunnel_enroll"
        private const val KEY_FINGERPRINT  = "fingerprint"
        private const val KEY_URL_PREFIX   = "url_"
        private const val KEY_SYNC_PREFIX  = "sync_"
        private const val KEY_OK_PREFIX    = "ok_"
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS    = 20_000

        /** Serialises enrollment requests so that concurrent syncs never race on storage. */
        private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "enrollment") }
        private val mainHandler = Handler(Looper.getMainLooper())

        /** Run [task] on the enrollment thread and wait for it (for background workers). */
        fun <T> runSerialized(task: () -> T): T = executor.submit(task).get()

        /** Run [task] on the enrollment thread and deliver its result on the main thread. */
        fun <T> runAsync(task: () -> T, onResult: (T) -> Unit) {
            executor.execute {
                val value = task()
                mainHandler.post { onResult(value) }
            }
        }
    }

    private val appContext = context.applicationContext
    private val configManager = ConfigManager(appContext)
    private val prefs: SharedPreferences = openSecurePrefs()

    // ── Queries ─────────────────────────────────────────────────────────────────

    fun isEnrolled(configId: String): Boolean = prefs.contains(KEY_URL_PREFIX + configId)

    /** Return when [configId] last got a fresh config from the server, or `null`. */
    fun lastSuccessfulSync(configId: String): Long? =
        prefs.getLong(KEY_OK_PREFIX + configId, 0L).takeIf { it > 0L }

    fun enrolledConfigIds(): List<String> =
        prefs.all.keys
            .filter { it.startsWith(KEY_URL_PREFIX) }
            .map { it.removePrefix(KEY_URL_PREFIX) }

    // ── Operations (blocking) ───────────────────────────────────────────────────

    /** Enroll this device by [url] right away, ignoring the sync throttle. */
    fun enroll(url: String): EnrollOutcome {
        val configId = EnrollmentProtocol.configIdFor(url)
        return performSync(configId, url, rememberLink = true)
    }

    /**
     * Re-check the enrollment behind [configId]. Return `null` if the config is not
     * enrolled or it was synced less than [MIN_SYNC_INTERVAL_MS] ago and [force] is false.
     */
    fun sync(configId: String, force: Boolean = false): EnrollOutcome? {
        val url = prefs.getString(KEY_URL_PREFIX + configId, null) ?: return null
        if (!force) {
            val last = prefs.getLong(KEY_SYNC_PREFIX + configId, 0L)
            if (System.currentTimeMillis() - last < MIN_SYNC_INTERVAL_MS) return null
        }
        return performSync(configId, url, rememberLink = false)
    }

    /** Re-check every stored enrollment (subject to the throttle unless [force]). */
    fun syncAll(force: Boolean = false): List<EnrollOutcome> =
        enrolledConfigIds().mapNotNull { sync(it, force) }

    /** Drop the enrollment link of [configId] (e.g. when the user deletes the config). */
    fun forget(configId: String) {
        prefs.edit()
            .remove(KEY_URL_PREFIX + configId)
            .remove(KEY_SYNC_PREFIX + configId)
            .remove(KEY_OK_PREFIX + configId)
            .apply()
    }

    // ── Internals ───────────────────────────────────────────────────────────────

    private fun performSync(configId: String, url: String, rememberLink: Boolean): EnrollOutcome {
        prefs.edit().putLong(KEY_SYNC_PREFIX + configId, System.currentTimeMillis()).apply()
        val result = request(url)
        val previous = configManager.getConfigs().firstOrNull { it.id == configId }
        val previousName = previous?.name

        when (result) {
            is EnrollResult.Success -> {
                configManager.saveConfig(VpnConfig(id = configId, name = configId, rawToml = result.toml))
                prefs.edit().apply {
                    if (rememberLink) putString(KEY_URL_PREFIX + configId, url)
                    putLong(KEY_OK_PREFIX + configId, System.currentTimeMillis())
                }.apply()
                Log.i(TAG, "Enrollment $configId: config updated")
            }
            is EnrollResult.Revoked -> {
                Log.w(TAG, "Enrollment $configId revoked: HTTP ${result.httpCode} ${result.error}")
                configManager.deleteConfig(configId)
                forget(configId)
                disconnectIfActive(configId)
            }
            is EnrollResult.RateLimited ->
                Log.w(TAG, "Enrollment $configId: rate limited, keeping current config")
            is EnrollResult.ClientError ->
                Log.w(TAG, "Enrollment $configId: HTTP ${result.httpCode}, keeping current config")
            is EnrollResult.TemporaryFailure ->
                Log.w(TAG, "Enrollment $configId: temporary failure, keeping current config")
        }

        val success = result as? EnrollResult.Success
        val name = success?.let { configManager.extractHostname(it.toml).ifBlank { null } }
            ?: success?.fileName?.removeSuffix(".toml")
            ?: previousName
            ?: EnrollmentProtocol.displayHost(url)
        val changed = when (result) {
            is EnrollResult.Success -> previous?.rawToml != result.toml
            is EnrollResult.Revoked -> previous != null
            else -> false
        }
        return EnrollOutcome(configId, name, result, changed)
    }

    private fun request(url: String): EnrollResult {
        val body = EnrollmentProtocol.buildRequestBody(fingerprint(), deviceName(), null)
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/toml, application/json")
            }
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            EnrollmentProtocol.classifyResponse(code, text, conn.getHeaderField("Content-Disposition"))
        } catch (e: IOException) {
            // Deliberately do not log the URL: it contains the secret token.
            EnrollResult.TemporaryFailure(e.javaClass.simpleName)
        } finally {
            conn?.disconnect()
        }
    }

    private fun disconnectIfActive(configId: String) {
        if (FireTunnelVpnService.activeConfigId != configId) return
        if (FireTunnelVpnService.lastKnownState == FireTunnelVpnService.STATE_DISCONNECTED) return
        Log.i(TAG, "Stopping VPN: its config was revoked")
        runCatching {
            appContext.startService(
                Intent(appContext, FireTunnelVpnService::class.java)
                    .setAction(FireTunnelVpnService.ACTION_DISCONNECT)
            )
        }.onFailure { Log.e(TAG, "Failed to stop VPN after revocation", it) }
    }

    /** Return the stored fingerprint, deriving it from `ANDROID_ID` on first use. */
    @SuppressLint("HardwareIds")
    private fun fingerprint(): String {
        prefs.getString(KEY_FINGERPRINT, null)?.let { return it }
        val machineId = Settings.Secure.getString(appContext.contentResolver, Settings.Secure.ANDROID_ID)
            ?.takeIf { it.isNotBlank() }
            ?: UUID.randomUUID().toString()
        return EnrollmentProtocol.fingerprint(machineId).also {
            prefs.edit().putString(KEY_FINGERPRINT, it).apply()
        }
    }

    private fun deviceName(): String =
        Settings.Global.getString(appContext.contentResolver, Settings.Global.DEVICE_NAME)
            ?.takeIf { it.isNotBlank() }
            ?: "${Build.MANUFACTURER} ${Build.MODEL}".trim()

    private fun openSecurePrefs(): SharedPreferences {
        fun create(): SharedPreferences = EncryptedSharedPreferences.create(
            PREFS_NAME,
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            appContext,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        return try {
            create()
        } catch (e: Exception) {
            // The keystore key can be lost (e.g. after a device restore); the stored
            // data is unreadable then, so start over — the user re-enters the link.
            Log.e(TAG, "Encrypted prefs unreadable, resetting", e)
            appContext.deleteSharedPreferences(PREFS_NAME)
            create()
        }
    }
}
