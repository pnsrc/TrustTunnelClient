package com.adguard.trusttunnel.log

import org.slf4j.LoggerFactory

/**
 * Bridge between the native C++ logging and SLF4J / logback-android.
 *
 * [log] is called directly by the native library via JNI:
 *   Java_com_adguard_trusttunnel_log_NativeLogger_log
 *
 * IMPORTANT: The companion-object init block intentionally contains NO native
 * calls.  Moving the System.loadLibrary + setupSlf4j() out of <clinit> prevents
 * ExceptionInInitializerError when the .so is absent, which would otherwise
 * crash every subsequent attempt to reference this class.
 */
class NativeLogger {
    companion object {
        private val LOG = LoggerFactory.getLogger("TrustTunnel_Native")

        // Level is kept in Kotlin; the native side calls setDefaultLogLevel()
        // after the library is loaded (see VpnService.setupNativeLogging()).
        var defaultLogLevel: NativeLoggerLevel = NativeLoggerLevel.INFO
            set(level) {
                field = level
                runCatching { setDefaultLogLevel(level.code) }
            }

        /**
         * Invoke once after [System.loadLibrary] succeeds to wire the native
         * log sink to SLF4J.
         */
        fun setupNativeLogging() {
            runCatching { setupSlf4j() }
        }

        /** Called by native code to emit a log line. */
        @JvmStatic
        fun log(level: Int, message: String?) {
            val lvl = runCatching { NativeLoggerLevel.getByCode(level) }
                .getOrDefault(NativeLoggerLevel.DEBUG)
            when (lvl) {
                NativeLoggerLevel.ERROR -> LOG.error(message)
                NativeLoggerLevel.WARN  -> LOG.warn(message)
                NativeLoggerLevel.INFO  -> LOG.info(message)
                NativeLoggerLevel.DEBUG -> LOG.debug(message)
                NativeLoggerLevel.TRACE -> LOG.trace(message)
            }
        }

        // ── Native stubs ───────────────────────────────────────────────────────
        @JvmStatic private external fun setDefaultLogLevel(level: Int)
        @JvmStatic private external fun getDefaultLogLevel0(): Int
        @JvmStatic private external fun setupSlf4j()
    }
}
