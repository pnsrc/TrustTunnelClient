package me.pnsrc.firetunnel

import android.os.Bundle
import android.os.Handler
import android.os.Looper
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
import java.io.IOException
import java.net.URL

class RulesFragment : Fragment() {

    private lateinit var rulesManager: RulesManager
    private lateinit var splitTunnelSwitch: MaterialSwitch
    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyText: TextView
    private lateinit var fab: FloatingActionButton

    private val mainHandler = Handler(Looper.getMainLooper())

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

        fab.setOnClickListener { showAddOptions() }
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

    // ── Add options ────────────────────────────────────────────────────────────

    private fun showAddOptions() {
        val options = arrayOf(
            getString(R.string.add_cidr_manually),
            getString(R.string.import_from_url)
        )
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.add_rule)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> showAddRuleDialog()
                    1 -> showDownloadDialog()
                }
            }
            .show()
    }

    // ── Manual CIDR dialog ─────────────────────────────────────────────────────

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

    // ── URL import dialog ──────────────────────────────────────────────────────

    private fun showDownloadDialog() {
        val padding = (24 * resources.displayMetrics.density).toInt()
        val editText = EditText(requireContext()).apply {
            setText(getString(R.string.import_url_default))
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                        android.text.InputType.TYPE_TEXT_VARIATION_URI
            setPadding(padding, padding / 2, padding, 0)
        }

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.import_url_title)
            .setMessage(R.string.import_url_hint)
            .setView(editText)
            .setPositiveButton(R.string.import_btn) { _, _ ->
                val url = editText.text.toString().trim()
                if (url.isNotBlank()) downloadAndImport(url)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun downloadAndImport(urlStr: String) {
        val snack = view?.let {
            Snackbar.make(it, getString(R.string.downloading), Snackbar.LENGTH_INDEFINITE)
                .also { s -> s.show() }
        }

        Thread {
            var imported = 0
            var errorMsg: String? = null
            try {
                val text = URL(urlStr).openStream().bufferedReader().use { it.readText() }
                val cidrs = text.lines()
                    .map { it.trim() }
                    .filter { it.isNotBlank() && !it.startsWith("#") && isValidCidr(it) }
                for (cidr in cidrs) {
                    rulesManager.addRule(cidr)
                    imported++
                }
            } catch (e: IOException) {
                errorMsg = e.message ?: "I/O error"
            } catch (e: Exception) {
                errorMsg = e.message ?: "Unknown error"
            }

            val finalImported = imported
            val finalError    = errorMsg
            mainHandler.post {
                snack?.dismiss()
                if (!isAdded) return@post
                if (finalError != null) {
                    showSnackbar(getString(R.string.import_failed, finalError))
                } else {
                    loadRules()
                    showSnackbar(getString(R.string.import_success, finalImported))
                }
            }
        }.start()
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
