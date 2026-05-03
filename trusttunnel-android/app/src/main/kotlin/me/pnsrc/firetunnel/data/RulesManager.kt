package me.pnsrc.firetunnel.data

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Persistent storage for IP/CIDR tunnel-exclusion rules.
 *
 * Rules are kept in SharedPreferences as a JSON array so they survive process
 * restarts.  The VPN service reads them when building the TUN interface to
 * apply split-tunnel routing (future native-core integration).
 */
data class ExclusionRule(
    val cidr: String,
    val enabled: Boolean = true
)

class RulesManager(context: Context) {

    private val prefs = context.getSharedPreferences("firetunnel_rules", Context.MODE_PRIVATE)

    // ── Split-tunnel toggle ────────────────────────────────────────────────────

    fun isSplitTunnelEnabled(): Boolean = prefs.getBoolean("split_tunnel", false)
    fun setSplitTunnelEnabled(enabled: Boolean) =
        prefs.edit().putBoolean("split_tunnel", enabled).apply()

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

    fun removeRule(cidr: String) = saveRules(getRules().filter { it.cidr != cidr })

    fun setRuleEnabled(cidr: String, enabled: Boolean) {
        saveRules(getRules().map { if (it.cidr == cidr) it.copy(enabled = enabled) else it })
    }

    /** Returns only CIDRs that are currently active (enabled = true). */
    fun getActiveCidrs(): List<String> =
        if (isSplitTunnelEnabled()) getRules().filter { it.enabled }.map { it.cidr }
        else emptyList()

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
