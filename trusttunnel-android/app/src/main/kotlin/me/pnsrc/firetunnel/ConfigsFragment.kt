package me.pnsrc.firetunnel

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import me.pnsrc.firetunnel.data.ConfigManager
import me.pnsrc.firetunnel.data.VpnConfig

class ConfigsFragment : Fragment() {

    private lateinit var configManager: ConfigManager
    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyView: TextView
    private lateinit var fab: ExtendedFloatingActionButton

    private val qrLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) loadConfigs()
    }

    private val fileLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let { importFromFile(it) }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_configs, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        configManager = ConfigManager(requireContext())

        recyclerView = view.findViewById(R.id.configsRecycler)
        emptyView    = view.findViewById(R.id.emptyText)
        fab          = view.findViewById(R.id.fabAdd)

        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        fab.setOnClickListener { showAddOptions() }
        loadConfigs()
    }

    override fun onResume() {
        super.onResume()
        loadConfigs()
    }

    // ── Config list ────────────────────────────────────────────────────────────

    private fun loadConfigs() {
        if (!isAdded) return
        val configs = configManager.getConfigs()
        val isEmpty = configs.isEmpty()
        emptyView.visibility    = if (isEmpty) View.VISIBLE else View.GONE
        recyclerView.visibility = if (isEmpty) View.GONE    else View.VISIBLE

        recyclerView.adapter = ConfigAdapter(configs.toMutableList()) { config ->
            AlertDialog.Builder(requireContext())
                .setTitle(R.string.delete_config_title)
                .setMessage(getString(R.string.delete_config_message, config.name))
                .setPositiveButton(R.string.delete) { _, _ ->
                    configManager.deleteConfig(config.id)
                    loadConfigs()
                    showSnackbar(getString(R.string.config_deleted, config.name))
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    // ── Add options ────────────────────────────────────────────────────────────

    private fun showAddOptions() {
        val options = arrayOf(
            getString(R.string.add_via_qr),
            getString(R.string.add_manually),
            getString(R.string.import_from_file)
        )
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.add_config)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> openQrScanner()
                    1 -> showManualInputDialog()
                    2 -> fileLauncher.launch("*/*")
                }
            }
            .show()
    }

    private fun openQrScanner() {
        if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                requireActivity(), arrayOf(Manifest.permission.CAMERA), 101
            )
        } else {
            qrLauncher.launch(Intent(requireContext(), QRScannerActivity::class.java))
        }
    }

    private fun showManualInputDialog() {
        val dialogView = LayoutInflater.from(requireContext())
            .inflate(R.layout.dialog_add_config, null)
        val nameInput  = dialogView.findViewById<TextInputEditText>(R.id.configNameInput)
        val tomlInput  = dialogView.findViewById<TextInputEditText>(R.id.configInput)

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.add_manually)
            .setView(dialogView)
            .setPositiveButton(R.string.save) { _, _ ->
                val toml       = tomlInput.text.toString().trim()
                val customName = nameInput.text.toString().trim()
                if (toml.isBlank()) {
                    showSnackbar(getString(R.string.config_empty_error))
                    return@setPositiveButton
                }
                val name = customName.ifBlank {
                    configManager.extractHostname(toml).ifBlank { "Config ${System.currentTimeMillis()}" }
                }
                configManager.saveConfig(
                    VpnConfig(id = System.currentTimeMillis().toString(), name = name, rawToml = toml)
                )
                loadConfigs()
                showSnackbar(getString(R.string.qr_imported, name))
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ── File import ────────────────────────────────────────────────────────────

    private fun importFromFile(uri: Uri) {
        runCatching {
            val toml = requireContext().contentResolver
                .openInputStream(uri)
                ?.bufferedReader()
                ?.use { it.readText() }
                ?.trim() ?: ""
            if (toml.isBlank()) {
                showSnackbar(getString(R.string.config_empty_error))
                return
            }
            val name = configManager.extractHostname(toml)
                .ifBlank {
                    // Fall back to file name from URI
                    uri.lastPathSegment
                        ?.substringAfterLast('/')
                        ?.removeSuffix(".toml")
                        ?.removeSuffix(".conf")
                        ?.ifBlank { null }
                        ?: "Config ${System.currentTimeMillis()}"
                }
            configManager.saveConfig(
                VpnConfig(id = System.currentTimeMillis().toString(), name = name, rawToml = toml)
            )
            loadConfigs()
            showSnackbar(getString(R.string.qr_imported, name))
        }.onFailure {
            showSnackbar(getString(R.string.import_file_error))
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 101 &&
            grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
        ) {
            qrLauncher.launch(Intent(requireContext(), QRScannerActivity::class.java))
        }
    }

    private fun showSnackbar(msg: String) {
        view?.let { Snackbar.make(it, msg, Snackbar.LENGTH_SHORT).show() }
    }
}

// ── RecyclerView adapter ──────────────────────────────────────────────────────

private class ConfigAdapter(
    private val items: MutableList<VpnConfig>,
    private val onDelete: (VpnConfig) -> Unit
) : RecyclerView.Adapter<ConfigAdapter.VH>() {

    inner class VH(view: View) : RecyclerView.ViewHolder(view) {
        val name: TextView    = view.findViewById(R.id.configName)
        val address: TextView = view.findViewById(R.id.configAddress)
        val deleteBtn: com.google.android.material.button.MaterialButton =
            view.findViewById(R.id.deleteBtn)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(LayoutInflater.from(parent.context).inflate(R.layout.item_config, parent, false))

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = items[position]
        holder.name.text = item.name
        // Show the first line that looks like a server address
        holder.address.text = item.rawToml.lines()
            .firstOrNull { it.contains("hostname") || it.contains("address") }
            ?.trim() ?: ""
        holder.deleteBtn.setOnClickListener { onDelete(item) }
    }

    override fun getItemCount() = items.size
}
