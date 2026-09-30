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
}
