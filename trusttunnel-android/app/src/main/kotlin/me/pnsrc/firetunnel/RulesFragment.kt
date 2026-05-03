package me.pnsrc.firetunnel

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.snackbar.Snackbar
import me.pnsrc.firetunnel.data.ExclusionRule
import me.pnsrc.firetunnel.data.RulesManager

class RulesFragment : Fragment() {

    private lateinit var rulesManager: RulesManager
    private lateinit var splitTunnelSwitch: MaterialSwitch
    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyText: TextView
    private lateinit var fab: FloatingActionButton

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_rules, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        rulesManager = RulesManager(requireContext())

        splitTunnelSwitch = view.findViewById(R.id.splitTunnelSwitch)
        recyclerView      = view.findViewById(R.id.rulesRecycler)
        emptyText         = view.findViewById(R.id.emptyRulesText)
        fab               = view.findViewById(R.id.fabAddRule)

        recyclerView.layoutManager = LinearLayoutManager(requireContext())

        splitTunnelSwitch.isChecked = rulesManager.isSplitTunnelEnabled()
        splitTunnelSwitch.setOnCheckedChangeListener { _, checked ->
            rulesManager.setSplitTunnelEnabled(checked)
        }

        fab.setOnClickListener { showAddRuleDialog() }
        loadRules()
    }

    private fun loadRules() {
        if (!isAdded) return
        val rules   = rulesManager.getRules()
        val isEmpty = rules.isEmpty()
        emptyText.visibility    = if (isEmpty) View.VISIBLE else View.GONE
        recyclerView.visibility = if (isEmpty) View.GONE    else View.VISIBLE

        recyclerView.adapter = RulesAdapter(
            rules.toMutableList(),
            onToggle = { cidr, enabled -> rulesManager.setRuleEnabled(cidr, enabled) },
            onDelete = { cidr ->
                rulesManager.removeRule(cidr)
                loadRules()
                showSnackbar(getString(R.string.rule_deleted, cidr))
            }
        )
    }

    private fun showAddRuleDialog() {
        val padding = (24 * resources.displayMetrics.density).toInt()
        val editText = EditText(requireContext()).apply {
            hint = "192.168.1.0/24"
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setPadding(padding, padding / 2, padding, 0)
        }

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.add_rule)
            .setMessage(R.string.add_rule_hint)
            .setView(editText)
            .setPositiveButton(R.string.save) { _, _ ->
                val cidr = editText.text.toString().trim()
                when {
                    cidr.isBlank()       -> return@setPositiveButton
                    !isValidCidr(cidr)   -> showSnackbar(getString(R.string.invalid_cidr))
                    else -> { rulesManager.addRule(cidr); loadRules() }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ── CIDR validation ────────────────────────────────────────────────────────

    private fun isValidCidr(cidr: String): Boolean = runCatching {
        val parts  = cidr.split("/")
        if (parts.size > 2) return false
        val ip     = parts[0]
        val prefix = parts.getOrNull(1)?.toIntOrNull()
        val octets = ip.split(".")
        if (octets.size == 4) {
            octets.all { it.toIntOrNull()?.let { v -> v in 0..255 } == true } &&
                (prefix == null || prefix in 0..32)
        } else {
            ip.contains(":") && (prefix == null || prefix in 0..128)
        }
    }.getOrDefault(false)

    private fun showSnackbar(msg: String) {
        view?.let { Snackbar.make(it, msg, Snackbar.LENGTH_SHORT).show() }
    }
}

// ── RecyclerView adapter ──────────────────────────────────────────────────────

private class RulesAdapter(
    private val items: MutableList<ExclusionRule>,
    private val onToggle: (String, Boolean) -> Unit,
    private val onDelete: (String) -> Unit
) : RecyclerView.Adapter<RulesAdapter.VH>() {

    inner class VH(view: View) : RecyclerView.ViewHolder(view) {
        val cidrText:  TextView      = view.findViewById(R.id.ruleText)
        val toggle:    MaterialSwitch = view.findViewById(R.id.ruleToggle)
        val deleteBtn: com.google.android.material.button.MaterialButton =
            view.findViewById(R.id.ruleDeleteBtn)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(LayoutInflater.from(parent.context).inflate(R.layout.item_rule, parent, false))

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = items[position]
        holder.cidrText.text  = item.cidr
        holder.toggle.isChecked = item.enabled
        holder.toggle.setOnCheckedChangeListener { _, checked -> onToggle(item.cidr, checked) }
        holder.deleteBtn.setOnClickListener { onDelete(item.cidr) }
    }

    override fun getItemCount() = items.size
}
