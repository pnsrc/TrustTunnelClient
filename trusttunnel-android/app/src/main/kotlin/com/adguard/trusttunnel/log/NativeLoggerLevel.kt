package com.adguard.trusttunnel.log

enum class NativeLoggerLevel(val code: Int) {
    ERROR(0),
    WARN(1),
    INFO(2),
    DEBUG(3),
    TRACE(4);

    companion object {
        private val map = entries.associateBy { it.code }
        fun getByCode(code: Int): NativeLoggerLevel =
            map[code] ?: throw IllegalArgumentException("Unknown log level code $code")
    }
}
