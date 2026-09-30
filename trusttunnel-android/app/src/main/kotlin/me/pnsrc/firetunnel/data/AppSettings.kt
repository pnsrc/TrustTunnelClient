package me.pnsrc.firetunnel.data

import android.content.Context

/** App-wide preferences from the Settings screen; every change applies immediately. */
class AppSettings(context: Context) {

    private val prefs = context.applicationContext.getSharedPreferences("settings", Context.MODE_PRIVATE)

    /** Show the connection as an Android 16 Live Update (status bar chip). */
    var liveUpdates: Boolean
        get() = prefs.getBoolean("live_updates", true)
        set(value) = prefs.edit().putBoolean("live_updates", value).apply()

    /** Core log level forced onto every config (`info`/`debug`/`trace`); `null` keeps the config's. */
    var logLevelOverride: String?
        get() = prefs.getString("log_level_override", null)?.takeIf { it in RoutingRules.LOG_LEVELS }
        set(value) = prefs.edit().putString("log_level_override", value).apply()

    // ── Appearance ───────────────────────────────────────────────────────────

    /** `system`, `light` or `dark`. */
    var themeMode: String
        get() = prefs.getString("theme_mode", THEME_SYSTEM)?.takeIf { it in THEME_MODES } ?: THEME_SYSTEM
        set(value) = prefs.edit().putString("theme_mode", value).apply()

    /** Take colours from the wallpaper (Android 12+) instead of [palette]. */
    var dynamicColor: Boolean
        get() = prefs.getBoolean("dynamic_color", true)
        set(value) = prefs.edit().putBoolean("dynamic_color", value).apply()

    /** One of [PALETTES]; used when [dynamicColor] is off or unavailable. */
    var palette: String
        get() = prefs.getString("palette", PALETTES.first())?.takeIf { it in PALETTES } ?: PALETTES.first()
        set(value) = prefs.edit().putString("palette", value).apply()

    /** Bumped on every appearance change so open screens know to recreate themselves. */
    val appearanceVersion: Int get() = prefs.getInt("appearance_version", 0)

    fun bumpAppearanceVersion() {
        prefs.edit().putInt("appearance_version", appearanceVersion + 1).apply()
    }

    companion object {
        const val THEME_SYSTEM = "system"
        const val THEME_LIGHT = "light"
        const val THEME_DARK = "dark"
        val THEME_MODES = listOf(THEME_SYSTEM, THEME_LIGHT, THEME_DARK)
        val PALETTES = listOf("fire", "ocean", "forest", "amethyst")
    }
}
