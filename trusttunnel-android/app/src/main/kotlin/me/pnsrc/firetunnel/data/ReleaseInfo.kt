package me.pnsrc.firetunnel.data

import org.json.JSONArray
import org.json.JSONObject

/** An app update published as a GitHub release with an `.apk` asset. */
data class ReleaseInfo(
    val version: AppVersion,
    val tag: String,
    val title: String,
    val notes: String,
    val pageUrl: String,
    val apkName: String,
    val apkUrl: String,
    val apkSize: Long,
    /** Lowercase hex SHA-256 of the APK from the asset's `digest`, if GitHub reports it. */
    val apkSha256: String?
)

/** Pure (Android-free) parsing of the GitHub releases API. */
object ReleaseParser {

    /**
     * Pick the newest release from a `GET /repos/{owner}/{repo}/releases` response
     * that ships an APK and is newer than [current]. Drafts are skipped; releases
     * without an `.apk` asset (e.g. desktop-only ones) are skipped too.
     */
    fun newestUpdate(releasesJson: String, current: AppVersion?): ReleaseInfo? {
        val releases = runCatching { JSONArray(releasesJson) }.getOrNull() ?: return null
        val candidates = (0 until releases.length())
            .mapNotNull { releases.optJSONObject(it) }
            .mapNotNull(::parseRelease)
        val newest = candidates.maxByOrNull { it.version } ?: return null
        return newest.takeIf { current == null || it.version > current }
    }

    private fun parseRelease(obj: JSONObject): ReleaseInfo? {
        if (obj.optBoolean("draft")) return null
        val tag = obj.optString("tag_name")
        val version = AppVersion.parse(tag) ?: return null
        val assets = obj.optJSONArray("assets") ?: return null
        val apk = (0 until assets.length())
            .mapNotNull { assets.optJSONObject(it) }
            .firstOrNull { it.optString("name").endsWith(".apk", ignoreCase = true) }
            ?: return null
        val url = apk.optString("browser_download_url")
        if (!url.startsWith("https://")) return null
        return ReleaseInfo(
            version = version,
            tag = tag,
            title = obj.optString("name").ifBlank { tag },
            notes = obj.optString("body").trim(),
            pageUrl = obj.optString("html_url"),
            apkName = apk.optString("name"),
            apkUrl = url,
            apkSize = apk.optLong("size", -1L),
            apkSha256 = apk.optString("digest")
                .takeIf { it.startsWith("sha256:", ignoreCase = true) }
                ?.substringAfter(':')?.lowercase()
                ?.takeIf { it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } }
        )
    }
}
