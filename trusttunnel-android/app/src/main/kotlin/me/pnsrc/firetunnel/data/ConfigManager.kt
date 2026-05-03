package me.pnsrc.firetunnel.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import java.net.URLDecoder

data class VpnConfig(
    val id: String,
    val name: String,
    val rawToml: String
)

private const val TAG = "ConfigManager"

class ConfigManager(private val context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("firetunnel_configs", Context.MODE_PRIVATE)

    fun getConfigs(): List<VpnConfig> =
        prefs.all
            .filter { it.key.startsWith("cfg_") }
            .mapNotNull { (key, value) ->
                val toml = value as? String ?: return@mapNotNull null
                val id   = key.removePrefix("cfg_")
                VpnConfig(id = id, name = extractHostname(toml).ifBlank { id }, rawToml = toml)
            }
            .sortedBy { it.name }

    fun saveConfig(config: VpnConfig) {
        prefs.edit().putString("cfg_${config.id}", config.rawToml).apply()
    }

    fun deleteConfig(id: String) {
        prefs.edit().remove("cfg_$id").apply()
    }

    /**
     * Decode a QR code from the Qt desktop client.
     * Qt pipeline: TOML → Base64 → URL-percent-encode → QR symbol.
     */
    fun parseQRCode(qrContent: String): VpnConfig? {
        for (toml in buildDecodeCandidates(qrContent)) {
            if (looksLikeToml(toml)) {
                val hostname = extractHostname(toml).ifBlank { "Imported" }
                Log.i(TAG, "QR parsed — hostname=$hostname")
                return VpnConfig(id = System.currentTimeMillis().toString(),
                                 name = hostname, rawToml = toml)
            }
        }
        Log.w(TAG, "Failed to decode QR (len=${qrContent.length})")
        return null
    }

    // ── Decode strategies ─────────────────────────────────────────────────────

    private fun buildDecodeCandidates(raw: String): List<String> {
        val results   = LinkedHashSet<String>()
        val urlDecoded = tryUrlDecode(raw)
        urlDecoded?.let { tryBase64Decode(it)?.let(results::add) }
        tryBase64Decode(raw)?.let(results::add)
        urlDecoded?.let(results::add)
        results.add(raw)
        return results.toList()
    }

    private fun tryUrlDecode(s: String): String? = runCatching {
        URLDecoder.decode(s, "UTF-8").takeIf { it != s }
    }.getOrNull()

    private fun tryBase64Decode(s: String): String? {
        val flags = intArrayOf(
            Base64.DEFAULT, Base64.URL_SAFE,
            Base64.DEFAULT or Base64.NO_WRAP, Base64.URL_SAFE or Base64.NO_WRAP
        )
        for (flag in flags) {
            runCatching {
                val bytes = Base64.decode(s.trim(), flag)
                if (bytes.isNotEmpty()) return String(bytes, Charsets.UTF_8)
            }
        }
        return null
    }

    // ── TOML field extraction ─────────────────────────────────────────────────

    fun extractHostname(toml: String): String {
        for (line in toml.lines()) {
            val t = line.trim()
            if (t.startsWith("hostname")) {
                val v = tomlValue(t); if (v.isNotBlank()) return v
            }
            if (t.startsWith("addresses")) {
                val first = Regex(""""([^"]+)"""").find(t)?.groupValues?.get(1) ?: ""
                if (first.isNotBlank()) return first.substringBefore(":")
            }
            if (t.startsWith("address")) {
                val v = tomlValue(t); if (v.isNotBlank()) return v.substringBefore(":")
            }
        }
        return ""
    }

    private fun tomlValue(line: String): String {
        val eq = line.indexOf('=')
        return if (eq < 0) ""
        else line.substring(eq + 1).trim().removeSurrounding("\"").removeSurrounding("'").trim()
    }

    private fun looksLikeToml(s: String) = s.contains('=') && s.any { it.isLetter() }
}
