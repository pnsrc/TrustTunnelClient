package me.pnsrc.firetunnel.data

import org.junit.Assert.assertEquals
import org.junit.Test

class StatsFormatTest {

    @Test
    fun bytes() {
        assertEquals("0 B", StatsFormat.bytes(0))
        assertEquals("0 B", StatsFormat.bytes(-5))
        assertEquals("1023 B", StatsFormat.bytes(1023))
        assertEquals("1.0 KB", StatsFormat.bytes(1024))
        assertEquals("1.5 KB", StatsFormat.bytes(1536))
        assertEquals("12.3 MB", StatsFormat.bytes((12.3 * 1024 * 1024).toLong()))
        assertEquals("1.25 GB", StatsFormat.bytes((1.25 * 1024 * 1024 * 1024).toLong()))
    }

    @Test
    fun speed() {
        assertEquals("0 B/s", StatsFormat.speed(0))
        assertEquals("2.0 KB/s", StatsFormat.speed(2048))
    }

    @Test
    fun uptime() {
        assertEquals("00:00", StatsFormat.uptime(0))
        assertEquals("01:05", StatsFormat.uptime(65))
        assertEquals("1:00:01", StatsFormat.uptime(3601))
    }
}
