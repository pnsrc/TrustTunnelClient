package me.pnsrc.firetunnel.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutingRulesTest {

    @Test
    fun `normalize accepts domains ips and cidrs`() {
        assertEquals("example.com", RoutingRules.normalize(" Example.COM. "))
        assertEquals("*.example.com", RoutingRules.normalize("*.example.com"))
        assertEquals("10.0.0.0/8", RoutingRules.normalize("10.0.0.0/8"))
        assertEquals("192.168.1.1", RoutingRules.normalize("192.168.1.1"))
        assertEquals("2001:db8::/32", RoutingRules.normalize("2001:DB8::/32"))
        assertEquals("::1", RoutingRules.normalize("::1"))
    }

    @Test
    fun `normalize rejects garbage`() {
        for (s in listOf("", "localhost", "a b.com", "10.0.0.0/33", "300.1.1.1", "example.com/8",
                "1::2::3", "http://example.com", "*.com.", "-a.com")) {
            assertNull(s, RoutingRules.normalize(s))
        }
    }

    private val config = """
        loglevel = "info"
        vpn_mode = "general"
        exclusions = [
            "corp.local",
            "10.0.0.0/8",
        ]

        [endpoint]
        hostname = "h"
        exclusions = ["must-stay"]
    """.trimIndent()

    @Test
    fun `off with no log level keeps config as is`() {
        assertEquals(config, RoutingRules.apply(config, ConfigOverrides()))
        assertEquals(config, RoutingRules.apply(config, ConfigOverrides(RoutingMode.BYPASS_LIST, emptyList())))
    }

    @Test
    fun `same mode extends config exclusions`() {
        val out = RoutingRules.apply(config, ConfigOverrides(RoutingMode.BYPASS_LIST, listOf("example.com", "bad host")))
        assertEquals("general", ConfigFields.topLevelString(out, "vpn_mode"))
        assertEquals(listOf("corp.local", "10.0.0.0/8", "example.com"), ConfigFields.topLevelArray(out, "exclusions"))
        // The old multi-line array is gone; the table's own key is untouched.
        assertEquals(1, Regex("\"corp\\.local\"").findAll(out).count())
        assertEquals(2, Regex("(?m)^exclusions").findAll(out).count())
        assertTrue(out.contains("exclusions = [\"must-stay\"]"))
        assertEquals("h", ConfigFields.firstEndpointAddress("$out\naddresses = [\"h\"]")?.host)
    }

    @Test
    fun `opposite mode replaces config exclusions`() {
        val out = RoutingRules.apply(config, ConfigOverrides(RoutingMode.ONLY_LIST, listOf("example.com")))
        assertEquals("selective", ConfigFields.topLevelString(out, "vpn_mode"))
        assertEquals(listOf("example.com"), ConfigFields.topLevelArray(out, "exclusions"))
    }

    @Test
    fun `log level override`() {
        val out = RoutingRules.apply(config, ConfigOverrides(logLevel = "debug"))
        assertEquals("debug", ConfigFields.topLevelString(out, "loglevel"))
        assertEquals(1, Regex("(?m)^loglevel").findAll(out).count())
        assertEquals(config, RoutingRules.apply(config, ConfigOverrides(logLevel = "verbose")))
    }
}
