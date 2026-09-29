package me.pnsrc.firetunnel

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.RadioGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.android.material.textfield.TextInputEditText
import me.pnsrc.firetunnel.data.AppRoutingManager
import me.pnsrc.firetunnel.data.AppRoutingMode
import me.pnsrc.firetunnel.data.InstalledApp

/**
 * Per-app split tunnelling: pick apps that bypass the VPN, or the only apps that
 * use it. Changes are saved immediately and applied on the next connection.
 */
class AppRoutingActivity : AppCompatActivity() {

    private lateinit var routing: AppRoutingManager
    private lateinit var modeGroup: RadioGroup
    private lateinit var searchInput: TextInputEditText
    private lateinit var progress: LinearProgressIndicator
    private lateinit var list: RecyclerView

    private val mainHandler = Handler(Looper.getMainLooper())
    private val selected = mutableSetOf<String>()
    private var allApps: List<InstalledApp> = emptyList()
    private val adapter = AppAdapter(selected) { pkg, checked -> onAppToggled(pkg, checked) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_routing)

        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        routing     = AppRoutingManager(this)
        modeGroup   = findViewById(R.id.appRoutingMode)
        searchInput = findViewById(R.id.appSearchInput)
        progress    = findViewById(R.id.appListProgress)
        list        = findViewById(R.id.appList)

        selected += routing.getSelectedPackages()

        modeGroup.check(radioIdFor(routing.getMode()))
        modeGroup.setOnCheckedChangeListener { _, id ->
            val mode = modeFor(id)
            routing.setMode(mode)
            adapter.enabled = mode != AppRoutingMode.OFF
        }
        adapter.enabled = routing.getMode() != AppRoutingMode.OFF

        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter
        searchInput.doAfterTextChanged { applyFilter() }

        loadApps()
    }

    private fun loadApps() {
        progress.visibility = View.VISIBLE
        val appContext = applicationContext
        Thread({
            val apps = AppRoutingManager(appContext).loadLaunchableApps()
            mainHandler.post {
                if (isFinishing || isDestroyed) return@post
                // Selected apps first; the order is fixed so rows don't jump on toggle.
                allApps = apps.sortedByDescending { it.packageName in selected }
                progress.visibility = View.GONE
                applyFilter()
            }
        }, "app-list").start()
    }

    private fun applyFilter() {
        val query = searchInput.text?.toString()?.trim().orEmpty()
        adapter.submit(
            if (query.isEmpty()) allApps
            else allApps.filter {
                it.label.contains(query, ignoreCase = true) || it.packageName.contains(query, ignoreCase = true)
            }
        )
    }

    private fun onAppToggled(pkg: String, checked: Boolean) {
        if (checked) selected += pkg else selected -= pkg
        routing.setSelectedPackages(selected)
    }

    private fun radioIdFor(mode: AppRoutingMode) = when (mode) {
        AppRoutingMode.OFF -> R.id.appRoutingOff
        AppRoutingMode.BYPASS_SELECTED -> R.id.appRoutingBypass
        AppRoutingMode.ONLY_SELECTED -> R.id.appRoutingOnly
    }

    private fun modeFor(radioId: Int) = when (radioId) {
        R.id.appRoutingBypass -> AppRoutingMode.BYPASS_SELECTED
        R.id.appRoutingOnly -> AppRoutingMode.ONLY_SELECTED
        else -> AppRoutingMode.OFF
    }
}

// ── RecyclerView adapter ──────────────────────────────────────────────────────

private class AppAdapter(
    private val selected: Set<String>,
    private val onToggle: (String, Boolean) -> Unit
) : RecyclerView.Adapter<AppAdapter.VH>() {

    private var items: List<InstalledApp> = emptyList()

    /** Whether the list is editable; it is dimmed while per-app routing is off. */
    var enabled: Boolean = true
        set(value) {
            if (field == value) return
            field = value
            notifyDataSetChanged()
        }

    fun submit(apps: List<InstalledApp>) {
        items = apps
        notifyDataSetChanged()
    }

    class VH(view: View) : RecyclerView.ViewHolder(view) {
        val icon: ImageView = view.findViewById(R.id.appIcon)
        val label: TextView = view.findViewById(R.id.appLabel)
        val pkg: TextView = view.findViewById(R.id.appPackage)
        val check: MaterialCheckBox = view.findViewById(R.id.appCheck)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(LayoutInflater.from(parent.context).inflate(R.layout.item_app, parent, false))

    override fun onBindViewHolder(holder: VH, position: Int) {
        val app = items[position]
        holder.icon.setImageDrawable(app.icon)
        holder.label.text = app.label
        holder.pkg.text = app.packageName
        holder.check.isChecked = app.packageName in selected
        holder.itemView.isEnabled = enabled
        holder.itemView.alpha = if (enabled) 1f else 0.5f
        holder.itemView.setOnClickListener {
            if (!enabled) return@setOnClickListener
            val checked = !holder.check.isChecked
            holder.check.isChecked = checked
            onToggle(app.packageName, checked)
        }
    }

    override fun getItemCount() = items.size
}
