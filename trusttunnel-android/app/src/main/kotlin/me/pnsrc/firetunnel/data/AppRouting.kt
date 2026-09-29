package me.pnsrc.firetunnel.data

/** How the per-app selection is applied to the VPN interface. */
enum class AppRoutingMode {
    /** Every app goes through the VPN. */
    OFF,

    /** Selected apps bypass the VPN, everything else goes through it. */
    BYPASS_SELECTED,

    /** Only selected apps go through the VPN. */
    ONLY_SELECTED;

    companion object {
        fun fromName(name: String?): AppRoutingMode =
            entries.firstOrNull { it.name == name } ?: OFF
    }
}

/**
 * Packages to pass to `VpnService.Builder`. Android forbids mixing
 * `addAllowedApplication` and `addDisallowedApplication`, so at most one set is non-empty.
 */
data class AppRoutingPlan(
    val allowed: Set<String>,
    val disallowed: Set<String>
)

/** Pure (Android-free) per-app split tunnelling logic. */
object AppRouting {

    /**
     * Turn the user's choice into an [AppRoutingPlan].
     *
     * FireTunnel itself must always stay outside the tunnel: its enrollment and
     * list-download requests must not loop through the VPN they configure. In
     * [AppRoutingMode.ONLY_SELECTED] mode that holds automatically because it is
     * never added to the allowed set. An empty selection in that mode would route
     * nothing, so it falls back to [AppRoutingMode.OFF].
     */
    fun plan(mode: AppRoutingMode, selected: Set<String>, ownPackage: String): AppRoutingPlan {
        val others = selected - ownPackage
        return when {
            mode == AppRoutingMode.ONLY_SELECTED && others.isNotEmpty() ->
                AppRoutingPlan(allowed = others, disallowed = emptySet())
            mode == AppRoutingMode.BYPASS_SELECTED ->
                AppRoutingPlan(allowed = emptySet(), disallowed = others + ownPackage)
            else ->
                AppRoutingPlan(allowed = emptySet(), disallowed = setOf(ownPackage))
        }
    }
}
