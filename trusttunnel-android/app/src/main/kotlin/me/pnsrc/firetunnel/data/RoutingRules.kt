package me.pnsrc.firetunnel.data

/** How the user's site/IP list is applied on top of the config. */
enum class RoutingMode {
    /** The list is not used; the config's own `vpn_mode`/`exclusions` apply. */
    OFF,

    /** Everything goes through the VPN except the listed sites and addresses. */
    BYPASS_LIST,

    /** Only the listed sites and addresses go through the VPN. */
    ONLY_LIST;

    companion object {
        fun fromName(name: String?): RoutingMode = entries.firstOrNull { it.name == name } ?: OFF
    }
}

/** Overrides the app applies to a config right before connecting. */
data class ConfigOverrides(
    val routingMode: RoutingMode = RoutingMode.OFF,
    val entries: List<String> = emptyList(),
    /** `info`, `debug` or `trace`; `null` keeps the config's own level. */
    val logLevel: String? = null
)

/** Pure (Android-free) rule validation and config rewriting. */
object RoutingRules {

    val LOG_LEVELS = listOf("info", "debug", "trace")

    private val IPV4 = Regex("""^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$""")
    private val DOMAIN = Regex("""^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$""")

    /** Normalise a user-entered rule, or return `null` if it is not a domain, IP or CIDR. */
    fun normalize(raw: String): String? {
        val s = raw.trim().lowercase().removeSuffix(".")
        if (s.isEmpty() || s.length > 253) return null
        val (addr, prefix) = s.split('/', limit = 2).let { it[0] to it.getOrNull(1) }
        return when {
            isIpv4(addr) -> s.takeIf { prefix == null || prefix.toIntOrNull() in 0..32 }
            isIpv6(addr) -> s.takeIf { prefix == null || prefix.toIntOrNull() in 0..128 }
            prefix == null && DOMAIN.matches(s) -> s
            else -> null
        }
    }

    private fun isIpv4(s: String) = IPV4.matches(s)

    private fun isIpv6(s: String): Boolean {
        if (':' !in s || s.count { it == ':' } > 7) return false
        if (s.count { it == ':' } < 2 || "::" in s.replaceFirst("::", "")) return false
        return s.split(':').all { it.isEmpty() || (it.length <= 4 && it.all { c -> c.isDigit() || c in 'a'..'f' }) }
    }

    /**
     * Apply [overrides] to [toml]. A list in the same mode as the config's own
     * `vpn_mode` extends its `exclusions`; in the opposite mode it replaces them,
     * because the config's list would then mean the reverse.
     */
    fun apply(toml: String, overrides: ConfigOverrides): String {
        val values = linkedMapOf<String, String>()
        overrides.logLevel?.takeIf { it in LOG_LEVELS }?.let { values["loglevel"] = ConfigBuilder.quote(it) }
        val entries = overrides.entries.mapNotNull(::normalize).distinct()
        if (overrides.routingMode != RoutingMode.OFF && entries.isNotEmpty()) {
            val mode = if (overrides.routingMode == RoutingMode.ONLY_LIST) "selective" else "general"
            val configMode = ConfigFields.topLevelString(toml, "vpn_mode") ?: "general"
            val inherited = if (configMode == mode) ConfigFields.topLevelArray(toml, "exclusions") else emptyList()
            values["vpn_mode"] = ConfigBuilder.quote(mode)
            values["exclusions"] = ConfigBuilder.array((inherited + entries).distinct())
        }
        return if (values.isEmpty()) toml else ConfigFields.overrideTopLevel(toml, values)
    }
}
