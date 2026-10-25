package me.pnsrc.firetunnel

import android.graphics.drawable.Drawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.LruCache
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.ConcatAdapter
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.recyclerview.widget.SimpleItemAnimator
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.chip.Chip
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.radiobutton.MaterialRadioButton
import com.google.android.material.textfield.TextInputEditText
import me.pnsrc.firetunnel.data.AppEntry
import me.pnsrc.firetunnel.data.AppListModel
import me.pnsrc.firetunnel.data.AppRoutingManager
import me.pnsrc.firetunnel.data.AppRoutingMode
import me.pnsrc.firetunnel.data.AppRow
import java.util.concurrent.Executors

/**
 * Per-app split tunnelling: a mode (all apps / selected bypass / only selected),
 * then every app that can use the network — user apps and, on request, system
 * ones — with search and filters. Changes are saved immediately and applied on
 * the next connection.
 */
class AppRoutingActivity : ThemedActivity() {

    private lateinit var routing: AppRoutingManager
    private val mainHandler = Handler(Looper.getMainLooper())
    private val iconExecutor = Executors.newFixedThreadPool(2) { r -> Thread(r, "app-icons") }
    private val icons = LruCache<String, Drawable>(256)

    private val selected = mutableSetOf<String>()
    /** Selection when the screen opened: decides the "Selected" section so rows don't jump. */
    private var pinned: Set<String> = emptySet()
    private var apps: List<AppEntry> = emptyList()
    private var loaded = false
    private var query = ""
    private var showSystem = false
    private var onlySelected = false

    private val header = HeaderAdapter()
    private val list = AppsAdapter()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_routing)

        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        routing = AppRoutingManager(this)
        selected += routing.getSelectedPackages()
        pinned = selected.toSet()

        findViewById<RecyclerView>(R.id.appList).apply {
            layoutManager = LinearLayoutManager(this@AppRoutingActivity)
            adapter = ConcatAdapter(header, list)
            // Re-bind rows in place: a change animation would swap the header's
            // view holder and steal focus from the search field while typing.
            (itemAnimator as? SimpleItemAnimator)?.supportsChangeAnimations = false
        }
        loadApps()
    }

    override fun onDestroy() {
        super.onDestroy()
        iconExecutor.shutdownNow()
    }

    private fun loadApps() {
        val appContext = applicationContext
        Thread({
            val result = AppRoutingManager(appContext).loadNetworkApps()
            mainHandler.post {
                if (isFinishing || isDestroyed) return@post
                apps = result
                loaded = true
                // Show system apps straight away if one is already selected.
                showSystem = showSystem || result.any { it.isSystem && it.packageName in selected }
                refresh()
            }
        }, "app-list").start()
    }

    private fun refresh() {
        list.submit(AppListModel.rows(apps, selected, pinned, query, showSystem, onlySelected))
        header.notifyItemChanged(0)
    }

    private fun toggle(pkg: String) {
        if (!selected.remove(pkg)) selected += pkg
        routing.setSelectedPackages(selected)
        refresh()
    }

    private fun loadIcon(pkg: String, into: ImageView) {
        icons.get(pkg)?.let {
            into.setImageDrawable(it)
            return
        }
        into.setImageDrawable(null)
        into.tag = pkg
        runCatching {
            iconExecutor.execute {
                val icon = routing.loadIcon(pkg) ?: return@execute
                mainHandler.post {
                    icons.put(pkg, icon)
                    if (into.tag == pkg) into.setImageDrawable(icon)
                }
            }
        }
    }

    // ── Header: mode, search, filters ──────────────────────────────────────────

    private inner class HeaderAdapter : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
        override fun getItemCount() = 1

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder =
            object : RecyclerView.ViewHolder(
                LayoutInflater.from(parent.context).inflate(R.layout.view_app_routing_header, parent, false)
            ) {}

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            val v = holder.itemView
            val mode = routing.getMode()
            bindMode(v.findViewById(R.id.appModeOff), AppRoutingMode.OFF, mode,
                R.string.app_routing_mode_off, R.string.app_routing_mode_off_sub)
            bindMode(v.findViewById(R.id.appModeBypass), AppRoutingMode.BYPASS_SELECTED, mode,
                R.string.app_routing_mode_bypass, R.string.app_routing_mode_bypass_sub)
            bindMode(v.findViewById(R.id.appModeOnly), AppRoutingMode.ONLY_SELECTED, mode,
                R.string.app_routing_mode_only, R.string.app_routing_mode_only_sub)

            v.findViewById<View>(R.id.appListProgress).visibility = if (loaded) View.GONE else View.VISIBLE
            v.findViewById<View>(R.id.appListEmpty).visibility =
                if (loaded && list.itemCount == 0) View.VISIBLE else View.GONE

            val chipSelected = v.findViewById<Chip>(R.id.chipOnlySelected)
            val chipSystem = v.findViewById<Chip>(R.id.chipSystem)
            chipSelected.text = getString(R.string.app_routing_filter_selected_count, selected.size)
            chipSelected.setOnCheckedChangeListener(null)
            chipSystem.setOnCheckedChangeListener(null)
            chipSelected.isChecked = onlySelected
            chipSystem.isChecked = showSystem
            chipSelected.setOnCheckedChangeListener { _, checked -> onlySelected = checked; refresh() }
            chipSystem.setOnCheckedChangeListener { _, checked -> showSystem = checked; refresh() }

            // The search field keeps focus and text across re-binds; wire it once per view.
            val search = v.findViewById<TextInputEditText>(R.id.appSearchInput)
            if (search.getTag(R.id.appSearchInput) == null) {
                search.setTag(R.id.appSearchInput, true)
                search.doAfterTextChanged {
                    query = it?.toString().orEmpty()
                    refresh()
                }
            }
        }

        private fun bindMode(row: View, value: AppRoutingMode, current: AppRoutingMode, titleRes: Int, subRes: Int) {
            row.findViewById<TextView>(R.id.modeTitle).setText(titleRes)
            row.findViewById<TextView>(R.id.modeSubtitle).setText(subRes)
            row.findViewById<MaterialRadioButton>(R.id.modeRadio).isChecked = value == current
            row.contentDescription = getString(titleRes)
            ViewCompat.setStateDescription(row, getString(if (value == current) R.string.state_on else R.string.state_off))
            row.setOnClickListener {
                if (value == routing.getMode()) return@setOnClickListener
                routing.setMode(value)
                header.notifyItemChanged(0)
                list.notifyItemRangeChanged(0, list.itemCount)
            }
        }
    }

    // ── App list ───────────────────────────────────────────────────────────────

    private inner class AppsAdapter : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
        private var rows: List<AppRow> = emptyList()

        fun submit(newRows: List<AppRow>) {
            rows = newRows
            notifyDataSetChanged()
        }

        override fun getItemCount() = rows.size

        override fun getItemViewType(position: Int) = if (rows[position] is AppRow.Header) 0 else 1

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val layout = if (viewType == 0) R.layout.item_app_section else R.layout.item_app
            return object : RecyclerView.ViewHolder(LayoutInflater.from(parent.context).inflate(layout, parent, false)) {}
        }

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            when (val row = rows[position]) {
                is AppRow.Header -> (holder.itemView as TextView).text = getString(when (row.section) {
                    AppRow.Section.SELECTED -> R.string.app_routing_section_selected
                    AppRow.Section.APPS -> R.string.app_routing_section_apps
                    AppRow.Section.SYSTEM -> R.string.app_routing_section_system
                }, row.count)
                is AppRow.App -> bindApp(holder.itemView, row)
            }
        }

        private fun bindApp(v: View, row: AppRow.App) {
            val app = row.entry
            val enabled = routing.getMode() != AppRoutingMode.OFF
            loadIcon(app.packageName, v.findViewById(R.id.appIcon))
            v.findViewById<TextView>(R.id.appLabel).text = app.label
            v.findViewById<TextView>(R.id.appPackage).text = app.packageName
            v.findViewById<View>(R.id.appSystemBadge).visibility = if (app.isSystem) View.VISIBLE else View.GONE
            v.findViewById<MaterialSwitch>(R.id.appSwitch).apply {
                isChecked = row.selected
                isEnabled = enabled
            }
            v.isSelected = row.selected
            v.isEnabled = enabled
            v.alpha = if (enabled) 1f else 0.5f
            v.contentDescription = app.label
            ViewCompat.setStateDescription(v, getString(if (row.selected) R.string.state_on else R.string.state_off))
            v.setOnClickListener { if (enabled) toggle(app.packageName) }
        }
    }
}
