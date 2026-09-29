package me.pnsrc.firetunnel.data

import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest

/**
 * Outcome of a single `POST <enroll link>` request.
 *
 * The split between [Revoked] and [TemporaryFailure] is the important part of the
 * protocol: 403/404 are an administrator's decision and the config must be wiped,
 * while network errors and 5xx must never touch the last working config.
 */
sealed class EnrollResult {
    /** 200 — [toml] is the fresh config; [fileName] comes from `Content-Disposition`. */
    data class Success(val toml: String, val fileName: String?) : EnrollResult()

    /** 403 `device_revoked` / `no_access`, 404 `unknown_link` — wipe the config. */
    data class Revoked(val httpCode: Int, val error: String?, val message: String?) : EnrollResult()

    /** 400 and other unexpected 4xx — a client-side problem, the config is kept. */
    data class ClientError(val httpCode: Int, val message: String?) : EnrollResult()

    /** 429 — too many requests, retry no sooner than in a minute. */
    data object RateLimited : EnrollResult()

    /** 5xx or a network error — keep working with the old config. */
    data class TemporaryFailure(val message: String?) : EnrollResult()
}

/**
 * Pure (Android-free) part of the FireTunnel device enrollment protocol:
 * deeplink parsing, fingerprint derivation, request body and response classification.
 */
object EnrollmentProtocol {
    const val DEEPLINK_SCHEME = "firetunnel"
    const val DEEPLINK_HOST   = "enroll"
    const val DEEPLINK_PARAM  = "url"

    const val ERROR_DEVICE_REVOKED = "device_revoked"
    const val ERROR_NO_ACCESS      = "no_access"
    const val ERROR_UNKNOWN_LINK   = "unknown_link"

    private const val FINGERPRINT_SALT = ":firetunnel"
    private const val CONFIG_ID_PREFIX = "enroll_"

    /**
     * Extract the HTTPS enrollment URL from user input.
     *
     * Accepts both `firetunnel://enroll?url=<percent-encoded https url>` and a bare
     * `https://…/enroll/<token>` link copied from the dashboard. Returns `null` for
     * anything else, including plain `http://` links: the link is a secret and must
     * not travel unencrypted.
     */
    fun parseEnrollLink(raw: String): String? {
        val input = raw.trim()
        if (input.isEmpty()) return null
        val uri = runCatching { URI(input) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null

        val target = when (scheme) {
            DEEPLINK_SCHEME -> {
                if (!DEEPLINK_HOST.equals(uri.host ?: uri.authority, ignoreCase = true)) return null
                queryParam(uri.rawQuery, DEEPLINK_PARAM) ?: return null
            }
            "https" -> input
            else -> return null
        }
        return target.trim().takeIf(::isValidHttpsUrl)
    }

    /** Return the host of an enrollment URL for display, without the secret token. */
    fun displayHost(url: String): String =
        runCatching { URI(url).host }.getOrNull().orEmpty()

    /** Compute `sha256(machineId + ":firetunnel")` as lowercase hex. */
    fun fingerprint(machineId: String): String = sha256Hex(machineId + FINGERPRINT_SALT)

    /**
     * Derive a stable config id from the enrollment URL so that repeated syncs
     * overwrite the same stored config instead of creating duplicates.
     */
    fun configIdFor(url: String): String = CONFIG_ID_PREFIX + sha256Hex(url).take(16)

    /** Build the JSON body `{fingerprint, name, user}`; blank optional fields are omitted. */
    fun buildRequestBody(fingerprint: String, name: String?, user: String?): String =
        JSONObject().apply {
            put("fingerprint", fingerprint)
            name?.takeIf { it.isNotBlank() }?.let { put("name", it) }
            user?.takeIf { it.isNotBlank() }?.let { put("user", it) }
        }.toString()

    /** Map an HTTP response to an [EnrollResult]. */
    fun classifyResponse(httpCode: Int, body: String, contentDisposition: String?): EnrollResult =
        when {
            httpCode == 200 -> {
                val toml = body.trim()
                if (toml.isEmpty()) EnrollResult.ClientError(httpCode, null)
                else EnrollResult.Success(toml, fileNameFromContentDisposition(contentDisposition))
            }
            httpCode == 403 || httpCode == 404 -> {
                val (error, message) = parseErrorBody(body)
                EnrollResult.Revoked(httpCode, error, message)
            }
            httpCode == 429 -> EnrollResult.RateLimited
            httpCode >= 500 -> EnrollResult.TemporaryFailure(parseErrorBody(body).second)
            else -> EnrollResult.ClientError(httpCode, parseErrorBody(body).second)
        }

    /** Parse `{"error": "...", "message": "..."}`; missing or malformed fields yield `null`. */
    fun parseErrorBody(body: String): Pair<String?, String?> {
        val json = runCatching { JSONObject(body) }.getOrNull() ?: return null to null
        fun field(key: String) = json.optString(key, "").trim().ifEmpty { null }
        return field("error") to field("message")
    }

    /** Extract `filename` from a `Content-Disposition` header value. */
    fun fileNameFromContentDisposition(header: String?): String? {
        if (header.isNullOrBlank()) return null
        val match = Regex("""filename\s*=\s*(?:"([^"]*)"|([^;\s]+))""", RegexOption.IGNORE_CASE)
            .find(header) ?: return null
        val name = match.groupValues[1].ifEmpty { match.groupValues[2] }.trim()
        return name.substringAfterLast('/').substringAfterLast('\\').ifEmpty { null }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private fun queryParam(rawQuery: String?, key: String): String? {
        if (rawQuery.isNullOrEmpty()) return null
        for (pair in rawQuery.split('&')) {
            val eq = pair.indexOf('=')
            if (eq <= 0) continue
            if (decode(pair.substring(0, eq)) == key) return decode(pair.substring(eq + 1))
        }
        return null
    }

    private fun decode(s: String): String = URLDecoder.decode(s, "UTF-8")

    private fun isValidHttpsUrl(url: String): Boolean {
        val uri = runCatching { URI(url) }.getOrNull() ?: return false
        return uri.scheme.equals("https", ignoreCase = true)
            && !uri.host.isNullOrBlank()
            && !uri.rawPath.isNullOrEmpty() && uri.rawPath != "/"
    }

    private fun sha256Hex(s: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(s.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}
