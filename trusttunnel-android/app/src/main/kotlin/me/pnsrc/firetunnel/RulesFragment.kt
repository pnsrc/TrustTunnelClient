package me.pnsrc.firetunnel

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.PopupMenu
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.ConcatAdapter
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.radiobutton.MaterialRadioButton
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import me.pnsrc.firetunnel.data.AppRoutingManager
import me.pnsrc.firetunnel.data.AppRoutingMode
import me.pnsrc.firetunnel.data.ExclusionRule
import me.pnsrc.firetunnel.data.RoutingMode
import me.pnsrc.firetunnel.data.RoutingRules
import me.pnsrc.firetunnel.data.RulesManager
import java.io.IOException
import java.net.URL

/**
 * Rules tab: per-app routing, then a list of sites and addresses with a mode
 * saying whether they bypass the VPN or are the only thing that uses it. The
 * list is applied to the config when connecting (see [RoutingRules.apply]).
 */
class RulesFragment : Fragment() {

    private lateinit var rulesManager: RulesManager
    private val mainHandler = Handler(Looper.getMainLooper())
    private val headerAdapter = HeaderAdapter { bindHeader(it) }
    private val rulesAdapter = RulesAdapter(
        onToggle = { rule, enabled -> rulesManager.setRuleEnabled(rule.cidr, enabled) },
        onDelete = { rule ->
            rulesManager.removeRule(rule.cidr)
            reload()
            showSnackbar(getString(R.string.rule_deleted, rule.cidr))
        }
    )

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_rules, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        rulesManager = RulesManager(requireContext())
        view.findViewById<RecyclerView>(R.id.rulesRecycler).apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = ConcatAdapter(headerAdapter, rulesAdapter)
        }
        reload()
    }

    override fun onResume() {
        super.onResume()
        headerAdapter.notifyItemChanged(0) // the app selection may have changed
    }

    private fun reload() {
        if (!isAdded) return
        rulesAdapter.submit(rulesManager.getRules())
        headerAdapter.notifyItemChanged(0)
    }

    // ── Header ─────────────────────────────────────────────────────────────────

    private fun bindHeader(header: View) {
        if (!isAdded) return
        SettingRow(header.findViewById(R.id.rowApps))
            .bind(R.drawable.ic_ft_apps, getString(R.string.app_routing_title), appRoutingSummary())
            .asLink { startActivity(Intent(requireContext(), AppRoutingActivity::class.java)) }

        val mode = rulesManager.getMode()
        bindMode(header.findViewById(R.id.modeOff), RoutingMode.OFF, mode,
            R.string.rules_mode_off, R.string.rules_mode_off_sub)
        bindMode(header.findViewById(R.id.modeBypass), RoutingMode.BYPASS_LIST, mode,
            R.string.rules_mode_bypass, R.string.rules_mode_bypass_sub)
        bindMode(header.findViewById(R.id.modeOnly), RoutingMode.ONLY_LIST, mode,
            R.string.rules_mode_only, R.string.rules_mode_only_sub)

        val count = rulesAdapter.itemCount
        header.findViewById<TextView>(R.id.rulesListTitle).text =
            resources.getQuantityString(R.plurals.rules_list_title, count, count)
        header.findViewById<View>(R.id.rulesEmpty).visibility = if (count == 0) View.VISIBLE else View.GONE
        header.findViewById<MaterialButton>(R.id.rulesAdd).setOnClickListener { showAddDialog() }
        header.findViewById<MaterialButton>(R.id.rulesImport).setOnClickListener { showImportDialog() }
        header.findViewById<MaterialButton>(R.id.rulesMenu).apply {
            visibility = if (count == 0) View.INVISIBLE else View.VISIBLE
            setOnClickListener { showListMenu(it) }
        }
    }

    private fun bindMode(row: View, value: RoutingMode, current: RoutingMode, titleRes: Int, subRes: Int) {
        row.findViewById<TextView>(R.id.modeTitle).setText(titleRes)
        row.findViewById<TextView>(R.id.modeSubtitle).setText(subRes)
        row.findViewById<MaterialRadioButton>(R.id.modeRadio).isChecked = value == current
        row.contentDescription = getString(titleRes)
        row.isSelected = value == current
        row.setOnClickListener {
            if (value == rulesManager.getMode()) return@setOnClickListener
            rulesManager.setMode(value)
            headerAdapter.notifyItemChanged(0)
            if (value != RoutingMode.OFF && rulesAdapter.itemCount == 0) {
                showSnackbar(getString(R.string.rules_mode_needs_entries))
            }
        }
    }

    private fun appRoutingSummary(): String {
        val routing = AppRoutingManager(requireContext())
        val count = routing.getSelectedPackages().size
        return when (routing.getMode()) {
            AppRoutingMode.OFF -> getString(R.string.app_routing_summary_off)
            AppRoutingMode.BYPASS_SELECTED ->
                resources.getQuantityString(R.plurals.app_routing_summary_bypass, count, count)
            AppRoutingMode.ONLY_SELECTED ->
                if (count == 0) getString(R.string.app_routing_summary_only_empty)
                else resources.getQuantityString(R.plurals.app_routing_summary_only, count, count)
        }
    }

    private fun showListMenu(anchor: View) {
        PopupMenu(requireContext(), anchor).apply {
            menu.add(R.string.rules_clear)
            setOnMenuItemClickListener {
                MaterialAlertDialogBuilder(requireContext())
                    .setTitle(R.string.rules_clear)
                    .setMessage(R.string.rules_clear_confirm)
                    .setPositiveButton(R.string.rules_clear) { _, _ ->
                        rulesManager.clear()
                        reload()
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
                true
            }
            show()
        }
    }

    // ── Add / import ───────────────────────────────────────────────────────────

    private fun textInputDialogView(hintRes: Int, helperRes: Int, multiLine: Boolean, initial: String = ""): Pair<View, TextInputEditText> {
        val layout = TextInputLayout(requireContext(), null,
            com.google.android.material.R.attr.textInputOutlinedStyle).apply {
            hint = getString(hintRes)
            helperText = getString(helperRes)
        }
        val input = TextInputEditText(layout.context).apply {
            setText(initial)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                (if (multiLine) android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
                 else android.text.InputType.TYPE_TEXT_VARIATION_URI)
            if (multiLine) minLines = 3
        }
        layout.addView(input)
        val pad = (24 * resources.displayMetrics.density).toInt()
        val frame = android.widget.FrameLayout(requireContext()).apply {
            setPadding(pad, pad / 3, pad, 0)
            addView(layout)
        }
        return frame to input
    }

    /** Add one or more entries typed or pasted by the user, one per line. */
    private fun showAddDialog() {
        val (view, input) = textInputDialogView(R.string.rules_add_hint, R.string.rules_add_helper, multiLine = true)
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.rules_add)
            .setView(view)
            .setPositiveButton(R.string.save) { _, _ -> addEntries(input.text?.toString().orEmpty().lines()) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun addEntries(raw: List<String>): Int {
        val candidates = raw.map { it.substringBefore('#').trim() }.filter { it.isNotEmpty() }
        val valid = candidates.mapNotNull(RoutingRules::normalize)
        val added = rulesManager.addRules(valid)
        reload()
        val skipped = candidates.size - valid.size
        showSnackbar(
            if (skipped == 0) resources.getQuantityString(R.plurals.rules_added, added, added)
            else getString(R.string.rules_added_skipped,
                resources.getQuantityString(R.plurals.rules_added, added, added), skipped)
        )
        return added
    }

    /** Download a plain-text list (one entry per line, `#` comments) and add it. */
    private fun showImportDialog() {
        val (view, input) = textInputDialogView(R.string.rules_import_hint, R.string.import_url_hint,
            multiLine = false, initial = getString(R.string.import_url_default))
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.import_url_title)
            .setView(view)
            .setPositiveButton(R.string.import_btn) { _, _ ->
                val url = input.text?.toString()?.trim().orEmpty()
                if (url.startsWith("https://") || url.startsWith("http://")) downloadAndImport(url)
                else showSnackbar(getString(R.string.import_failed, url))
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun downloadAndImport(urlStr: String) {
        val snack = view?.let {
            Snackbar.make(it, getString(R.string.downloading), Snackbar.LENGTH_INDEFINITE).also { s -> s.show() }
        }
        Thread({
            val result = runCatching {
                URL(urlStr).openStream().bufferedReader().use { it.readText() }.lines()
            }
            mainHandler.post {
                snack?.dismiss()
                if (!isAdded) return@post
                result
                    .onSuccess { lines -> addEntries(lines) }
                    .onFailure { e ->
                        val reason = if (e is IOException) e.message else e.javaClass.simpleName
                        showSnackbar(getString(R.string.import_failed, reason ?: ""))
                    }
            }
        }, "rules-import").start()
    }

    private fun showSnackbar(msg: String) {
        view?.let { Snackbar.make(it, msg, Snackbar.LENGTH_SHORT).show() }
    }
}

// ── Adapters ─────────────────────────────────────────────────────────────────

/** Single header row; re-bound whenever the fragment calls notifyItemChanged(0). */
private class HeaderAdapter(private val onBind: (View) -> Unit) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder =
        object : RecyclerView.ViewHolder(
            LayoutInflater.from(parent.context).inflate(R.layout.view_rules_header, parent, false)
        ) {}

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) = onBind(holder.itemView)

    override fun getItemCount() = 1
}

private class RulesAdapter(
    private val onToggle: (ExclusionRule, Boolean) -> Unit,
    private val onDelete: (ExclusionRule) -> Unit
) : RecyclerView.Adapter<RulesAdapter.VH>() {

    private var items: List<ExclusionRule> = emptyList()

    fun submit(rules: List<ExclusionRule>) {
        items = rules
        notifyDataSetChanged()
    }

    class VH(view: View) : RecyclerView.ViewHolder(view) {
        val icon: ImageView = view.findViewById(R.id.ruleIcon)
        val text: TextView = view.findViewById(R.id.ruleText)
        val toggle: MaterialSwitch = view.findViewById(R.id.ruleToggle)
        val delete: MaterialButton = view.findViewById(R.id.ruleDeleteBtn)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(LayoutInflater.from(parent.context).inflate(R.layout.item_rule, parent, false))

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = items[position]
        val ctx = holder.itemView.context
        val isAddress = item.cidr.first().isDigit() || ':' in item.cidr
        holder.icon.setImageResource(if (isAddress) R.drawable.ic_ft_server else R.drawable.ic_ft_globe)
        holder.text.text = item.cidr
        holder.toggle.setOnCheckedChangeListener(null)
        holder.toggle.isChecked = item.enabled
        holder.toggle.contentDescription = item.cidr
        holder.toggle.setOnCheckedChangeListener { _, checked -> onToggle(item, checked) }
        holder.delete.contentDescription = ctx.getString(R.string.rules_delete_desc, item.cidr)
        holder.delete.setOnClickListener { onDelete(item) }
    }

    override fun getItemCount() = items.size
}
