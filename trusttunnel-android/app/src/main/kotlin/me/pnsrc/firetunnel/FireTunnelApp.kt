package me.pnsrc.firetunnel

import android.app.Application
import me.pnsrc.firetunnel.data.AppSettings

/**
 * Application entry point: applies the light/dark choice before any screen is
 * shown (colours are applied per screen by [ThemedActivity]) and schedules the
 * background enrollment check.
 *
 * logback-android 2.x auto-initialises via its own ContentProvider registered
 * in the merged manifest, so no explicit setup is needed here.
 */
class FireTunnelApp : Application() {
    override fun onCreate() {
        super.onCreate()
        ThemedActivity.applyNightMode(AppSettings(this))
        EnrollmentCheckWorker.schedule(this)
    }
}
