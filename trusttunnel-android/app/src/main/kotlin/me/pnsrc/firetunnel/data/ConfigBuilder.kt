package me.pnsrc.firetunnel.data

/** What the config constructor collects. Blank optional fields are left out of the TOML. */
data class ConfigForm(
    /** `host` or `host:port`; the port defaults to 443. */
    val server: String,
    /** Extra `host:port` addresses; the client pings them all and picks the fastest. */
    val extraAddresses: List<String> = emptyList(),
    val username: String,
    val password: String,
    val http3: Boolean = false,
    /** Empty: the core's default (AdGuard DNS). */
    val dnsUpstreams: List<String> = emptyList(),
    val customSni: String = "",
    val antiDpi: Boolean = false,
    val postQuantum: Boolean = true,
    val skipVerification: Boolean = false
)

/** Pure (Android-free) builder of a TrustTunnel TOML config from [ConfigForm]. */
object ConfigBuilder {

    enum class Problem { SERVER, USERNAME, PASSWORD, EXTRA_ADDRESS }

    /** Return the fields that must be fixed before [build]; empty when the form is valid. */
    fun validate(form: ConfigForm): Set<Problem> = buildSet {
        if (ConfigFields.parseHostPort(form.server) == null || form.server.any { it.isWhitespace() }) add(Problem.SERVER)
        if (form.username.isBlank()) add(Problem.USERNAME)
        if (form.password.isEmpty()) add(Problem.PASSWORD)
        if (form.extraAddresses.any { ConfigFields.parseHostPort(it) == null }) add(Problem.EXTRA_ADDRESS)
    }

    fun build(form: ConfigForm): String {
        val main = ConfigFields.parseHostPort(form.server.trim())
            ?: throw IllegalArgumentException("invalid server")
        val addresses = (listOf(main) + form.extraAddresses.mapNotNull { ConfigFields.parseHostPort(it) })
            .map(::formatAddress)
            .distinct()
        return buildString {
            appendLine("loglevel = \"info\"")
            appendLine("vpn_mode = \"general\"")
            appendLine("post_quantum_group_enabled = ${form.postQuantum}")
            appendLine()
            appendLine("[endpoint]")
            appendLine("hostname = ${quote(main.host)}")
            appendLine("addresses = ${array(addresses)}")
            appendLine("username = ${quote(form.username.trim())}")
            appendLine("password = ${quote(form.password)}")
            appendLine("upstream_protocol = ${quote(if (form.http3) "http3" else "http2")}")
            if (form.dnsUpstreams.isNotEmpty()) appendLine("dns_upstreams = ${array(form.dnsUpstreams)}")
            if (form.customSni.isNotBlank()) appendLine("custom_sni = ${quote(form.customSni.trim())}")
            appendLine("anti_dpi = ${form.antiDpi}")
            appendLine("skip_verification = ${form.skipVerification}")
        }
    }

    /** Split user input (lines, commas, spaces) into trimmed non-empty items. */
    fun splitList(raw: String): List<String> =
        raw.split(Regex("[\\s,;]+")).map { it.trim() }.filter { it.isNotEmpty() }.distinct()

    /** Encode [s] as a TOML basic string. */
    fun quote(s: String): String = buildString {
        append('"')
        for (c in s) {
            when (c) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (c < ' ') append(String.format("\\u%04x", c.code)) else append(c)
            }
        }
        append('"')
    }

    fun array(items: List<String>): String = items.joinToString(", ", "[", "]") { quote(it) }

    private fun formatAddress(hp: HostPort): String =
        if (':' in hp.host) "[${hp.host}]:${hp.port}" else "${hp.host}:${hp.port}"
}
