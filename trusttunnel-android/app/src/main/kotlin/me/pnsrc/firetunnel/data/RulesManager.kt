package me.pnsrc.firetunnel.data

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Persistent storage for the "Sites and addresses" list (domains, IPs, CIDRs).
 *
 * Rules are kept in SharedPreferences as a JSON array. The list is applied to the
 * config right before connecting (see [RoutingRules.apply]) according to [getMode].
 */
data class ExclusionRule(
    val cidr: String,
    val enabled: Boolean = true
)

class RulesManager(context: Context) {

    private val prefs = context.getSharedPreferences("firetunnel_rules", Context.MODE_PRIVATE)

    // ── Mode ───────────────────────────────────────────────────────────────────

    /** Return how the list is applied; the old "split tunnel" switch maps to [RoutingMode.BYPASS_LIST]. */
    fun getMode(): RoutingMode {
        prefs.getString("routing_mode", null)?.let { return RoutingMode.fromName(it) }
        return if (prefs.getBoolean("split_tunnel", false)) RoutingMode.BYPASS_LIST else RoutingMode.OFF
    }

    fun setMode(mode: RoutingMode) {
        prefs.edit().putString("routing_mode", mode.name).remove("split_tunnel").apply()
    }

    // ── Rule CRUD ──────────────────────────────────────────────────────────────

    fun getRules(): List<ExclusionRule> {
        val json = prefs.getString("exclusion_rules", "[]") ?: "[]"
        return runCatching {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val obj = arr.getJSONObject(i)
                ExclusionRule(cidr = obj.getString("cidr"),
                              enabled = obj.optBoolean("enabled", true))
            }
        }.getOrDefault(emptyList())
    }

    fun addRule(cidr: String) {
        val rules = getRules().toMutableList()
        if (rules.none { it.cidr == cidr }) {
            rules.add(ExclusionRule(cidr = cidr, enabled = true))
            saveRules(rules)
        }
    }

    /** Add many entries with one write; return how many were new. */
    fun addRules(entries: List<String>): Int {
        val rules = getRules().toMutableList()
        val known = rules.mapTo(HashSet()) { it.cidr }
        val added = entries.filter { known.add(it) }
        if (added.isNotEmpty()) saveRules(rules + added.map { ExclusionRule(cidr = it, enabled = true) })
        return added.size
    }

    fun clear() = saveRules(emptyList())

    fun removeRule(cidr: String) = saveRules(getRules().filter { it.cidr != cidr })

    fun setRuleEnabled(cidr: String, enabled: Boolean) {
        saveRules(getRules().map { if (it.cidr == cidr) it.copy(enabled = enabled) else it })
    }

    /** Return the overrides to apply when connecting: the mode and the enabled entries. */
    fun overrides(logLevel: String?): ConfigOverrides =
        ConfigOverrides(getMode(), getRules().filter { it.enabled }.map { it.cidr }, logLevel)

    private fun saveRules(rules: List<ExclusionRule>) {
        val arr = JSONArray()
        rules.forEach { rule ->
            arr.put(JSONObject().apply {
                put("cidr", rule.cidr)
                put("enabled", rule.enabled)
            })
        }
        prefs.edit().putString("exclusion_rules", arr.toString()).apply()
    }
}
