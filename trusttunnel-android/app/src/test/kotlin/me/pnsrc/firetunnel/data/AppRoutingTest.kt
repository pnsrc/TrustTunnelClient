package me.pnsrc.firetunnel.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRoutingTest {

    private val own = "me.pnsrc.firetunnel"

    @Test
    fun `off bypasses only the app itself`() {
        val plan = AppRouting.plan(AppRoutingMode.OFF, setOf("a", "b"), own)
        assertEquals(AppRoutingPlan(allowed = emptySet(), disallowed = setOf(own)), plan)
    }

    @Test
    fun `bypass mode disallows selected apps and the app itself`() {
        val plan = AppRouting.plan(AppRoutingMode.BYPASS_SELECTED, setOf("a", "b"), own)
        assertEquals(AppRoutingPlan(allowed = emptySet(), disallowed = setOf("a", "b", own)), plan)
    }

    @Test
    fun `bypass mode with empty selection bypasses only the app itself`() {
        val plan = AppRouting.plan(AppRoutingMode.BYPASS_SELECTED, emptySet(), own)
        assertEquals(AppRoutingPlan(allowed = emptySet(), disallowed = setOf(own)), plan)
    }

    @Test
    fun `only mode allows selected apps and never the app itself`() {
        val plan = AppRouting.plan(AppRoutingMode.ONLY_SELECTED, setOf("a", own), own)
        assertEquals(AppRoutingPlan(allowed = setOf("a"), disallowed = emptySet()), plan)
    }

    @Test
    fun `only mode with empty selection falls back to off`() {
        for (selection in listOf(emptySet(), setOf(own))) {
            val plan = AppRouting.plan(AppRoutingMode.ONLY_SELECTED, selection, own)
            assertEquals(AppRoutingPlan(allowed = emptySet(), disallowed = setOf(own)), plan)
        }
    }

    @Test
    fun `allowed and disallowed are never both set`() {
        for (mode in AppRoutingMode.entries) {
            for (selection in listOf(emptySet(), setOf("a"), setOf("a", "b", own))) {
                val plan = AppRouting.plan(mode, selection, own)
                assertTrue("$mode $selection", plan.allowed.isEmpty() || plan.disallowed.isEmpty())
            }
        }
    }

    @Test
    fun `mode parsing falls back to off`() {
        assertEquals(AppRoutingMode.BYPASS_SELECTED, AppRoutingMode.fromName("BYPASS_SELECTED"))
        assertEquals(AppRoutingMode.OFF, AppRoutingMode.fromName(null))
        assertEquals(AppRoutingMode.OFF, AppRoutingMode.fromName("garbage"))
    }
}
