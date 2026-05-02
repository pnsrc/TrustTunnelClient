package com.trusttunnel.android.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import java.net.URLDecoder

/**
 * Lightweight representation of a saved VPN configuration.
 * The full raw TOML is preserved so it can be passed verbatim to the VPN service.
 */
data class VpnConfig(
    val id: String,
    /** Display name derived from the `hostname` field (or `addresses[0]`) in the TOML */
    val name: String,
    /** Raw TOML content exactly as decoded from the QR code */
    val rawToml: String
)

private const val TAG = "ConfigManager"

class ConfigManager(private val context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("trusttunnel_configs", Context.MODE_PRIVATE)

    // ── Public API ────────────────────────────────────────────────────────────

    fun getConfigs(): List<VpnConfig> =
        prefs.all
            .filter { it.key.startsWith("cfg_") }
            .mapNotNull { (key, value) ->
                val toml = value as? String ?: return@mapNotNull null
                val id = key.removePrefix("cfg_")
                val name = extractHostname(toml).ifBlank { id }
                VpnConfig(id = id, name = name, rawToml = toml)
            }
            .sortedBy { it.name }

    fun saveConfig(config: VpnConfig) {
        prefs.edit().putString("cfg_${config.id}", config.rawToml).apply()
    }

    fun deleteConfig(id: String) {
        prefs.edit().remove("cfg_$id").apply()
    }

    /**
     * Decode a QR code produced by the Qt desktop client.
     *
     * Qt pipeline:  TOML bytes  →  Base64  →  URL-percent-encode  →  QR API
     *
     * The QR-server stores the percent-encoded Base64 inside the QR symbol, so
     * the scanner returns the percent-encoded Base64.  We try multiple decode
     * strategies and pick the first result that looks like TOML.
     */
    fun parseQRCode(qrContent: String): VpnConfig? {
        for (toml in buildDecodeCandidates(qrContent)) {
            if (looksLikeToml(toml)) {
                val hostname = extractHostname(toml).ifBlank { "Imported" }
                Log.i(TAG, "QR parsed — hostname=$hostname")
                return VpnConfig(
                    id = System.currentTimeMillis().toString(),
                    name = hostname,
                    rawToml = toml
                )
            }
        }
        Log.w(TAG, "Failed to decode QR (len=${qrContent.length})")
        return null
    }

    // ── Decode strategies ─────────────────────────────────────────────────────

    private fun buildDecodeCandidates(raw: String): List<String> {
        val results = LinkedHashSet<String>()

        val urlDecoded = tryUrlDecode(raw)

        // Main Qt flow: URL-decode → Base64-decode
        urlDecoded?.let { tryBase64Decode(it)?.let(results::add) }

        // Plain Base64 (QR server already URL-decoded before encoding)
        tryBase64Decode(raw)?.let(results::add)

        // URL-decoded string is already TOML (no Base64)
        urlDecoded?.let(results::add)

        // Raw string is TOML directly
        results.add(raw)

        return results.toList()
    }

    private fun tryUrlDecode(s: String): String? = runCatching {
        URLDecoder.decode(s, "UTF-8").takeIf { it != s }
    }.getOrNull()

    private fun tryBase64Decode(s: String): String? {
        val flags = intArrayOf(
            Base64.DEFAULT,
            Base64.URL_SAFE,
            Base64.DEFAULT or Base64.NO_WRAP,
            Base64.URL_SAFE or Base64.NO_WRAP
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

    /**
     * Extract the server hostname for display purposes.
     * Checks `hostname`, first entry of `addresses`, and `address` fields.
     */
    fun extractHostname(toml: String): String {
        for (line in toml.lines()) {
            val t = line.trim()
            if (t.startsWith("hostname")) {
                val v = tomlValue(t)
                if (v.isNotBlank()) return v
            }
            if (t.startsWith("addresses")) {
                // addresses = ["vpn.example.com:443", ...]
                val first = Regex(""""([^"]+)"""").find(t)?.groupValues?.get(1) ?: ""
                if (first.isNotBlank()) return first.substringBefore(":")
            }
            if (t.startsWith("address")) {
                val v = tomlValue(t)
                if (v.isNotBlank()) return v.substringBefore(":")
            }
        }
        return ""
    }

    private fun tomlValue(line: String): String {
        val eq = line.indexOf('=')
        if (eq < 0) return ""
        return line.substring(eq + 1).trim()
            .removeSurrounding("\"")
            .removeSurrounding("'")
            .trim()
    }

    /** A decoded string is TOML if it contains `=` and at least one letter */
    private fun looksLikeToml(s: String) = s.contains('=') && s.any { it.isLetter() }
}
