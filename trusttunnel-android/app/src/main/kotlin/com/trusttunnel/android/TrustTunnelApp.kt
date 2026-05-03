package com.trusttunnel.android

import android.app.Application
import ch.qos.logback.classic.LoggerContext
import ch.qos.logback.classic.android.AndroidContextUtil
import org.slf4j.LoggerFactory

/**
 * Custom Application entry point.
 *
 * logback-android 2.x auto-initialises via a ContentProvider registered in
 * the library's merged manifest.  Calling [AndroidContextUtil.setupLoggingContext]
 * here is a belt-and-suspenders measure: it guarantees that the ${DATA_DIR}
 * property substitution in assets/logback.xml resolves to the correct
 * app-private path even on edge-case startup paths where the ContentProvider
 * fires after the first Logger is obtained.
 *
 * Without a correct DATA_DIR the RollingFileAppender silently fails to create
 * the log file (the path resolves to a bare "/logs/trusttunnel.log" which is
 * unwritable), leaving only the Logcat appender active.
 */
class TrustTunnelApp : Application() {

    override fun onCreate() {
        super.onCreate()
        // Ensure the app Context is available to logback-android before any
        // Logger is obtained.  LoggerFactory.getILoggerFactory() returns the
        // already-initialised LoggerContext (or triggers initialisation now).
        val lc = LoggerFactory.getILoggerFactory() as? LoggerContext ?: return
        AndroidContextUtil(this).setupLoggingContext(lc)
    }
}
