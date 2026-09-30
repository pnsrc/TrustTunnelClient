package me.pnsrc.firetunnel.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ConfigFieldsTest {

    // ── dns_upstreams ───────────────────────────────────────────────────────────

    @Test
    fun `no upstreams uses adguard dns`() {
        val toml = "loglevel = \"info\"\n[endpoint]\nhostname = \"h\"\n"
        assertEquals(emptyList<String>(), ConfigFields.effectiveDnsUpstreams(toml))
        assertEquals(ConfigFields.ADGUARD_DNS, ConfigFields.tunDnsServers(toml))
    }

    @Test
    fun `legacy top level upstreams use fake dns`() {
        val toml = "dns_upstreams = [\"1.1.1.1\", \"8.8.8.8\"]\n[endpoint]\nhostname = \"h\"\n"
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), ConfigFields.effectiveDnsUpstreams(toml))
        assertEquals(ConfigFields.FAKE_DNS, ConfigFields.tunDnsServers(toml))
    }

    @Test
    fun `endpoint upstreams take precedence over legacy`() {
        val toml = """
            dns_upstreams = ["1.1.1.1"]
            [endpoint]
            dns_upstreams = ["tls://dns.adguard-dns.com"]
        """.trimIndent()
        assertEquals(listOf("tls://dns.adguard-dns.com"), ConfigFields.effectiveDnsUpstreams(toml))
    }

    @Test
    fun `empty endpoint upstreams override legacy like the core does`() {
        val toml = "dns_upstreams = [\"1.1.1.1\"]\n[endpoint]\ndns_upstreams = []\n"
        assertEquals(emptyList<String>(), ConfigFields.effectiveDnsUpstreams(toml))
        assertEquals(ConfigFields.ADGUARD_DNS, ConfigFields.tunDnsServers(toml))
    }

    @Test
    fun `multi line arrays comments and literal strings`() {
        val toml = """
            # dns_upstreams = ["commented.out"]
            [endpoint]
            dns_upstreams = [ # resolvers
                "https://dns.example/dns-query#frag",  # DoH
                'quic://dns.example',
            ]
            hostname = "h"
        """.trimIndent()
        assertEquals(
            listOf("https://dns.example/dns-query#frag", "quic://dns.example"),
            ConfigFields.effectiveDnsUpstreams(toml)
        )
    }

    @Test
    fun `upstreams in other tables are ignored`() {
        val toml = "[listener.tun]\ndns_upstreams = [\"9.9.9.9\"]\n"
        assertEquals(emptyList<String>(), ConfigFields.effectiveDnsUpstreams(toml))
    }

    // ── endpoint address ────────────────────────────────────────────────────────

    @Test
    fun `first endpoint address`() {
        val toml = "addresses = [\"ignored:1\"]\n[endpoint]\naddresses = [\"fvpn.ddns.net:443\", \"1.2.3.4:8443\"]\n"
        assertEquals(HostPort("fvpn.ddns.net", 443), ConfigFields.firstEndpointAddress(toml))
    }

    @Test
    fun `missing endpoint address`() {
        assertNull(ConfigFields.firstEndpointAddress("[endpoint]\nhostname = \"h\"\n"))
        assertNull(ConfigFields.firstEndpointAddress("[endpoint]\naddresses = []\n"))
    }

    @Test
    fun `host port parsing`() {
        assertEquals(HostPort("1.2.3.4", 8443), ConfigFields.parseHostPort("1.2.3.4:8443"))
        assertEquals(HostPort("example.com", 443), ConfigFields.parseHostPort("example.com"))
        assertEquals(HostPort("2001:db8::1", 443), ConfigFields.parseHostPort("[2001:db8::1]:443"))
        assertEquals(HostPort("2001:db8::1", 443), ConfigFields.parseHostPort("[2001:db8::1]"))
        assertEquals(HostPort("2001:db8::1", 443), ConfigFields.parseHostPort("2001:db8::1"))
        assertNull(ConfigFields.parseHostPort(""))
        assertNull(ConfigFields.parseHostPort("host:notaport"))
        assertNull(ConfigFields.parseHostPort("host:70000"))
        assertNull(ConfigFields.parseHostPort(":443"))
        assertNull(ConfigFields.parseHostPort("[]:443"))
    }

    // ── upstream protocol ───────────────────────────────────────────────────────

    @Test
    fun `upstream protocol`() {
        assertEquals("HTTP/2", ConfigFields.upstreamProtocol("[endpoint]\nhostname = \"h\"\n"))
        assertEquals("HTTP/3", ConfigFields.upstreamProtocol("[endpoint]\nupstream_protocol = \"http3\" # quic\n"))
        assertEquals("HTTP/2", ConfigFields.upstreamProtocol("upstream_protocol = \"http3\"\n[endpoint]\n"))
    }
}
