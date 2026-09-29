package me.pnsrc.firetunnel.data

/** A `host:port` endpoint address. */
data class HostPort(val host: String, val port: Int)

/**
 * Pure (Android-free) extraction of the few TrustTunnel TOML fields the Android
 * app itself needs; the native core parses the full config.
 */
object ConfigFields {

    /** AdGuard DNS unfiltered — what the core uses when no upstreams are configured. */
    val ADGUARD_DNS = listOf("46.243.231.30", "46.243.231.31", "2a10:50c0::1:ff", "2a10:50c0::2:ff")

    /**
     * Fake resolver address for the TUN interface. The core intercepts queries to it
     * and resolves them through the configured `dns_upstreams` (DoH/DoT/plain), which
     * cannot be handed to Android directly.
     */
    val FAKE_DNS = listOf("198.18.53.53")

    private const val DEFAULT_PORT = 443

    /**
     * Return the upstreams the core will actually use: `[endpoint].dns_upstreams`
     * if the key is present (even when empty), otherwise the legacy top-level key.
     */
    fun effectiveDnsUpstreams(toml: String): List<String> {
        val arrays = stringArrays(toml, "dns_upstreams")
        return arrays["endpoint"] ?: arrays[""] ?: emptyList()
    }

    /** Pick the DNS servers for the TUN interface the same way the reference Android service does. */
    fun tunDnsServers(toml: String): List<String> =
        if (effectiveDnsUpstreams(toml).isEmpty()) ADGUARD_DNS else FAKE_DNS

    /** Return the first `[endpoint].addresses` entry, parsed; `null` if absent or malformed. */
    fun firstEndpointAddress(toml: String): HostPort? =
        stringArrays(toml, "addresses")["endpoint"]?.firstOrNull()?.let(::parseHostPort)

    /** Parse `host`, `host:port`, `1.2.3.4:port`, `[v6]:port` or a bare IPv6 address. */
    fun parseHostPort(raw: String): HostPort? {
        val s = raw.trim()
        if (s.isEmpty()) return null
        if (s.startsWith("[")) {
            val end = s.indexOf(']')
            if (end <= 1) return null
            val host = s.substring(1, end)
            val rest = s.substring(end + 1)
            val port = if (rest.isEmpty()) DEFAULT_PORT else rest.removePrefix(":").toIntOrNull() ?: return null
            return HostPort(host, port).takeIf { port in 1..65535 }
        }
        if (s.count { it == ':' } > 1) return HostPort(s, DEFAULT_PORT) // bare IPv6
        val colon = s.lastIndexOf(':')
        if (colon < 0) return HostPort(s, DEFAULT_PORT)
        val host = s.substring(0, colon)
        val port = s.substring(colon + 1).toIntOrNull() ?: return null
        return HostPort(host, port).takeIf { host.isNotEmpty() && port in 1..65535 }
    }

    // ── Minimal TOML scanning ────────────────────────────────────────────────────

    /**
     * Collect string arrays named [key], keyed by the table they appear in
     * (`""` for the top level). Handles multi-line arrays and `#` comments.
     */
    private fun stringArrays(toml: String, key: String): Map<String, List<String>> {
        val result = mutableMapOf<String, List<String>>()
        var table = ""
        var collecting: StringBuilder? = null

        for (rawLine in toml.lines()) {
            val line = stripComment(rawLine).trim()
            val pending = collecting
            if (pending != null) {
                pending.append(' ').append(line)
                if (isArrayClosed(pending)) {
                    result[table] = quotedStrings(pending.toString())
                    collecting = null
                }
                continue
            }
            if (line.startsWith("[")) {
                table = line.trim('[', ']', ' ')
                continue
            }
            val eq = line.indexOf('=')
            if (eq <= 0 || line.substring(0, eq).trim() != key) continue
            val value = line.substring(eq + 1).trim()
            if (!value.startsWith("[")) continue
            val buf = StringBuilder(value)
            if (isArrayClosed(buf)) result[table] = quotedStrings(value) else collecting = buf
        }
        return result
    }

    /** Cut a trailing `#` comment, ignoring `#` inside "basic" or 'literal' strings. */
    private fun stripComment(line: String): String {
        val end = scan(line) { c -> if (c == '#') ScanStop.CUT else ScanStop.NO }
        return if (end >= 0) line.substring(0, end) else line
    }

    /** Return true once the array opened by the first `[` in [buf] is closed. */
    private fun isArrayClosed(buf: CharSequence): Boolean {
        var depth = 0
        return scan(buf) { c ->
            when (c) {
                '[' -> depth++
                ']' -> if (--depth == 0) return@scan ScanStop.CUT
            }
            ScanStop.NO
        } >= 0
    }

    private enum class ScanStop { NO, CUT }

    /**
     * Walk [text] outside of quoted strings, calling [onChar] for each unquoted
     * character; return the index where it asked to stop, or -1.
     */
    private inline fun scan(text: CharSequence, onChar: (Char) -> ScanStop): Int {
        var inBasic = false
        var inLiteral = false
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when {
                inBasic -> if (c == '\\') i++ else if (c == '"') inBasic = false
                inLiteral -> if (c == '\'') inLiteral = false
                c == '"' -> inBasic = true
                c == '\'' -> inLiteral = true
                onChar(c) == ScanStop.CUT -> return i
            }
            i++
        }
        return -1
    }

    private val QUOTED = Regex(""""((?:[^"\\]|\\.)*)"|'([^']*)'""")

    private fun quotedStrings(arrayText: String): List<String> =
        QUOTED.findAll(arrayText)
            .map { m -> m.groupValues[1].ifEmpty { m.groupValues[2] } }
            .filter { it.isNotBlank() }
            .toList()
}
