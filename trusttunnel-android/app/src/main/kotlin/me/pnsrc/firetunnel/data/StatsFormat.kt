package me.pnsrc.firetunnel.data

import java.util.Locale

/** Pure formatting helpers for traffic statistics. */
object StatsFormat {

    private val UNITS = listOf("B", "KB", "MB", "GB", "TB")

    /** Format a byte count with binary units: `512 B`, `1.5 KB`, `12.3 MB`, `1.25 GB`. */
    fun bytes(value: Long): String {
        if (value < 1024) return "${value.coerceAtLeast(0)} B"
        var v = value.toDouble()
        var unit = 0
        while (v >= 1024 && unit < UNITS.lastIndex) {
            v /= 1024
            unit++
        }
        val pattern = if (unit >= 3) "%.2f %s" else "%.1f %s"
        return String.format(Locale.US, pattern, v, UNITS[unit])
    }

    /** Format a transfer rate: `0 B/s`, `12.0 KB/s`. */
    fun speed(bytesPerSecond: Long): String = bytes(bytesPerSecond) + "/s"

    /** Format an uptime in seconds as `mm:ss` or `h:mm:ss`. */
    fun uptime(seconds: Long): String {
        val s = seconds.coerceAtLeast(0)
        val h = s / 3600
        val m = (s % 3600) / 60
        val sec = s % 60
        return if (h > 0) String.format(Locale.US, "%d:%02d:%02d", h, m, sec)
        else String.format(Locale.US, "%02d:%02d", m, sec)
    }
}
