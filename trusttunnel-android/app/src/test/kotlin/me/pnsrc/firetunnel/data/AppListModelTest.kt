package me.pnsrc.firetunnel.data

import me.pnsrc.firetunnel.data.AppRow.Section
import org.junit.Assert.assertEquals
import org.junit.Test

class AppListModelTest {

    private val apps = listOf(
        AppEntry("org.telegram", "Telegram", false),
        AppEntry("com.bank", "bank app", false),
        AppEntry("com.google.android.gms", "Google Play services", true),
        AppEntry("com.android.webview", "Android System WebView", true),
        AppEntry("com.zoom", "Zoom", false),
    )

    private fun shape(rows: List<AppRow>) = rows.map {
        when (it) {
            is AppRow.Header -> "#${it.section}:${it.count}"
            is AppRow.App -> it.entry.packageName + if (it.selected) "*" else ""
        }
    }

    @Test
    fun `selected first then user apps sorted, system hidden`() {
        val rows = AppListModel.rows(apps, selected = setOf("com.zoom"), pinned = setOf("com.zoom"))
        assertEquals(listOf("#SELECTED:1", "com.zoom*", "#APPS:2", "com.bank", "org.telegram"), shape(rows))
    }

    @Test
    fun `system section when shown`() {
        val rows = AppListModel.rows(apps, emptySet(), emptySet(), showSystem = true)
        assertEquals(listOf("#APPS:3", "com.bank", "org.telegram", "com.zoom",
            "#SYSTEM:2", "com.android.webview", "com.google.android.gms"), shape(rows))
    }

    @Test
    fun `pinned system app stays visible with system hidden`() {
        val rows = AppListModel.rows(apps, setOf("com.google.android.gms"), setOf("com.google.android.gms"))
        assertEquals("com.google.android.gms*", shape(rows)[1])
    }

    @Test
    fun `toggling does not move rows between sections`() {
        // Selected after the screen opened: stays in its section, only the switch changes.
        val rows = AppListModel.rows(apps, selected = setOf("org.telegram"), pinned = emptySet())
        assertEquals(listOf("#APPS:3", "com.bank", "org.telegram*", "com.zoom"), shape(rows))
    }

    @Test
    fun `search by label or package and only selected`() {
        assertEquals(listOf("#APPS:1", "org.telegram"), shape(AppListModel.rows(apps, emptySet(), emptySet(), query = "tele")))
        assertEquals(listOf("#SYSTEM:1", "com.google.android.gms"),
            shape(AppListModel.rows(apps, emptySet(), emptySet(), query = "gms", showSystem = true)))
        assertEquals(listOf("#SELECTED:1", "com.zoom*"),
            shape(AppListModel.rows(apps, setOf("com.zoom"), setOf("com.zoom"), onlySelected = true)))
        assertEquals(emptyList<String>(), shape(AppListModel.rows(apps, emptySet(), emptySet(), query = "nothing")))
    }
}
