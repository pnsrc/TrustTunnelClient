package me.pnsrc.firetunnel.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigBuilderTest {

    private val form = ConfigForm(server = "vpn.example.com", username = "ivan", password = "p\"a\\ss")

    @Test
    fun `minimal form builds a config the app can read back`() {
        val toml = ConfigBuilder.build(form)
        assertEquals(HostPort("vpn.example.com", 443), ConfigFields.firstEndpointAddress(toml))
        assertEquals("HTTP/2", ConfigFields.upstreamProtocol(toml))
        assertEquals(emptyList<String>(), ConfigFields.effectiveDnsUpstreams(toml))
        assertTrue(toml.contains("hostname = \"vpn.example.com\""))
        assertTrue(toml.contains("password = \"p\\\"a\\\\ss\""))
        assertFalse(toml.contains("custom_sni"))
    }

    @Test
    fun `full form`() {
        val toml = ConfigBuilder.build(form.copy(
            server = "vpn.example.com:8443",
            extraAddresses = listOf("203.0.113.5:443", "vpn.example.com:8443"),
            http3 = true,
            dnsUpstreams = listOf("tls://1.1.1.1"),
            customSni = "cdn.example.net",
            antiDpi = true
        ))
        assertTrue(toml.contains("addresses = [\"vpn.example.com:8443\", \"203.0.113.5:443\"]"))
        assertEquals("HTTP/3", ConfigFields.upstreamProtocol(toml))
        assertEquals(listOf("tls://1.1.1.1"), ConfigFields.effectiveDnsUpstreams(toml))
        assertTrue(toml.contains("custom_sni = \"cdn.example.net\""))
        assertTrue(toml.contains("anti_dpi = true"))
    }

    @Test
    fun validation() {
        assertEquals(emptySet<ConfigBuilder.Problem>(), ConfigBuilder.validate(form))
        val bad = ConfigBuilder.validate(ConfigForm(server = "bad host", username = " ", password = "",
            extraAddresses = listOf("x:99999")))
        assertEquals(ConfigBuilder.Problem.entries.toSet(), bad)
    }

    @Test
    fun `quote escapes control characters`() {
        assertEquals("\"a\\nb\\tc\\u0001\"", ConfigBuilder.quote("a\nb\tc\u0001"))
    }

    @Test
    fun `split list`() {
        assertEquals(listOf("a", "b", "c"), ConfigBuilder.splitList(" a,\nb ; c  a "))
    }
}
