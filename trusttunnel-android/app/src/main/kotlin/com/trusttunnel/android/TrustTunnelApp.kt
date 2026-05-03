package com.trusttunnel.android

import android.app.Application
import com.github.tony19.logback.android.LogbackAndroid

/**
 * Custom Application entry point.
 *
 * logback-android needs to be initialised with the app Context before any
 * Logger is obtained, so that the ${DATA_DIR} / ${EXT_DIR} property
 * substitutions in assets/logback.xml resolve to the correct paths.
 *
 * Without this call the RollingFileAppender silently fails to create
 * the log file (the path resolves to a bare "/logs/trusttunnel.log"
 * which is unwritable), leaving only the Logcat appender active.
 */
class TrustTunnelApp : Application() {

    override fun onCreate() {
        super.onCreate()
        // Wire logback-android to this application's Context.
        // Must be called before any LoggerFactory.getLogger() usage.
        LogbackAndroid.setup(this)
    }
}
