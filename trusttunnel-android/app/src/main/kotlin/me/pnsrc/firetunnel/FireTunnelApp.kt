package me.pnsrc.firetunnel

import android.app.Application
import com.google.android.material.color.DynamicColors

/**
 * Application entry point.
 *
 * [DynamicColors.applyToActivitiesIfAvailable] overlays wallpaper-derived
 * Material You colour tones on Android 12+ (API 31+).  On older devices it
 * is a no-op and the static Deep Orange fallback palette in themes.xml is used.
 *
 * logback-android 2.x auto-initialises via its own ContentProvider registered
 * in the merged manifest, so no explicit setup is needed here.
 */
class FireTunnelApp : Application() {
    override fun onCreate() {
        super.onCreate()
        DynamicColors.applyToActivitiesIfAvailable(this)
    }
}
