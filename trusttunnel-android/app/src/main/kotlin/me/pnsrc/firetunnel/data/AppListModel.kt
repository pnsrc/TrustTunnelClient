package me.pnsrc.firetunnel.data

/** What the app picker knows about an installed package (no Android types, so it is testable). */
data class AppEntry(
    val packageName: String,
    val label: String,
    val isSystem: Boolean
)

/** A row of the app picker: a section header or an app. */
sealed class AppRow {
    enum class Section { SELECTED, APPS, SYSTEM }

    data class Header(val section: Section, val count: Int) : AppRow()
    data class App(val entry: AppEntry, val selected: Boolean) : AppRow()
}

/** Pure (Android-free) layout of the app picker list. */
object AppListModel {

    /**
     * Build the rows: selected apps first, then user apps, then (if [showSystem])
     * system apps, each section sorted by label. [pinned] is the selection as it was
     * when the screen opened, so rows do not jump between sections while toggling;
     * [selected] is the live selection used for the switches. A [query] matches the
     * label or the package name; [onlySelected] keeps only selected apps.
     */
    fun rows(
        apps: List<AppEntry>,
        selected: Set<String>,
        pinned: Set<String>,
        query: String = "",
        showSystem: Boolean = false,
        onlySelected: Boolean = false
    ): List<AppRow> {
        val q = query.trim()
        val visible = apps.filter { app ->
            (q.isEmpty() || app.label.contains(q, ignoreCase = true) || app.packageName.contains(q, ignoreCase = true))
                && (!onlySelected || app.packageName in selected)
                // A selected system app stays visible even with system apps hidden.
                && (showSystem || !app.isSystem || app.packageName in pinned)
        }.sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })

        val (top, rest) = visible.partition { it.packageName in pinned }
        val (system, user) = rest.partition { it.isSystem }
        return buildList {
            section(AppRow.Section.SELECTED, top, selected)
            section(AppRow.Section.APPS, user, selected)
            section(AppRow.Section.SYSTEM, system, selected)
        }
    }

    private fun MutableList<AppRow>.section(section: AppRow.Section, apps: List<AppEntry>, selected: Set<String>) {
        if (apps.isEmpty()) return
        add(AppRow.Header(section, apps.size))
        apps.forEach { add(AppRow.App(it, it.packageName in selected)) }
    }
}
