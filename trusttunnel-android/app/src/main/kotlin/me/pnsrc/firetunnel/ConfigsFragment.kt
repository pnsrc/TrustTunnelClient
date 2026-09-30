package me.pnsrc.firetunnel

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.text.SpannableString
import android.text.format.DateUtils
import android.text.style.ForegroundColorSpan
import android.util.Base64
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.PopupMenu
import android.widget.RadioGroup
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.R as MaterialR
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import me.pnsrc.firetunnel.data.ConfigManager
import me.pnsrc.firetunnel.data.EnrollResult
import me.pnsrc.firetunnel.data.EnrollmentManager
import me.pnsrc.firetunnel.data.VpnConfig
import java.net.URLEncoder

class ConfigsFragment : Fragment() {

    private lateinit var configManager: ConfigManager
    private lateinit var recyclerView: RecyclerView
    private lateinit var content: View
    private lateinit var emptyState: View
    private lateinit var fab: ExtendedFloatingActionButton

    private val qrLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            loadConfigs()
            result.data?.getStringExtra(QRScannerActivity.EXTRA_ENROLL_LINK)?.let { link ->
                EnrollmentUi.confirmAndEnroll(requireActivity(), link) { loadConfigs() }
            }
        }
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
        content      = view.findViewById(R.id.configsContent)
        emptyState   = view.findViewById(R.id.emptyState)
        fab          = view.findViewById(R.id.fabAdd)

        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        fab.setOnClickListener { showAddOptions() }
        view.findViewById<MaterialButton>(R.id.emptyPasteLink).setOnClickListener {
            EnrollmentUi.promptForLink(requireActivity()) { loadConfigs() }
        }
        view.findViewById<MaterialButton>(R.id.emptyScanQr).setOnClickListener { openQrScanner() }
        view.findViewById<MaterialButton>(R.id.emptyOther).setOnClickListener { showAddOptions() }
        loadConfigs()
    }

    override fun onResume() {
        super.onResume()
        loadConfigs()
        if ((activity as? MainActivity)?.consumeAddSheetRequest() == true) showAddOptions()
    }

    // ── Config list ────────────────────────────────────────────────────────────

    private fun loadConfigs() {
        if (!isAdded || view == null) return
        val configs = configManager.getConfigs()
        val isEmpty = configs.isEmpty()
        emptyState.visibility = if (isEmpty) View.VISIBLE else View.GONE
        content.visibility    = if (isEmpty) View.GONE    else View.VISIBLE
        if (isEmpty) fab.hide() else fab.show()

        val enrollment = EnrollmentManager(requireContext())
        val enrollmentLabels = configs
            .filter { enrollment.isEnrolled(it.id) }
            .associate { it.id to enrollmentLabel(enrollment.lastSuccessfulSync(it.id)) }

        recyclerView.adapter = ConfigAdapter(
            items = configs,
            activeId = configManager.getActiveConfig(configs)?.id,
            enrollmentLabels = enrollmentLabels,
            onSelect = ::selectConfig,
            onMore = ::showConfigMenu
        )
    }

    private fun selectConfig(config: VpnConfig) {
        configManager.setActiveConfigId(config.id)
        loadConfigs()
        val connected = FireTunnelVpnService.lastKnownState == FireTunnelVpnService.STATE_CONNECTED
        if (connected && config.id != FireTunnelVpnService.activeConfigId) {
            showSnackbar(getString(R.string.server_reconnect_hint))
        }
    }

    /** Describe an enrolled config: "From dashboard · updated 5 min ago". */
    private fun enrollmentLabel(lastSync: Long?): String {
        val now = System.currentTimeMillis()
        val updated = when {
            lastSync == null -> return getString(R.string.enrolled_badge)
            now - lastSync < DateUtils.MINUTE_IN_MILLIS -> getString(R.string.enrolled_just_now)
            else -> DateUtils.getRelativeTimeSpanString(lastSync, now, DateUtils.MINUTE_IN_MILLIS).toString()
        }
        return getString(R.string.enrolled_synced, updated)
    }

    // ── Per-config actions ─────────────────────────────────────────────────────

    /**
     * Enrolled configs are owned by the dashboard: they can be refreshed but not
     * edited (the next sync would overwrite the edit) or exported as a QR code
     * (that would bypass device enrollment). Local configs are the opposite.
     */
    private fun showConfigMenu(anchor: View, config: VpnConfig) {
        val enrolled = EnrollmentManager(requireContext()).isEnrolled(config.id)
        val popup = PopupMenu(requireContext(), anchor)
        popup.menuInflater.inflate(R.menu.config_item, popup.menu)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) popup.setForceShowIcon(true)
        val iconTint = UiKit.themeColor(requireContext(), MaterialR.attr.colorOnSurfaceVariant)
        for (i in 0 until popup.menu.size()) popup.menu.getItem(i).icon?.mutate()?.setTint(iconTint)
        popup.menu.findItem(R.id.action_config_edit).isVisible = !enrolled
        popup.menu.findItem(R.id.action_config_qr).isVisible = !enrolled
        popup.menu.findItem(R.id.action_config_refresh).isVisible = enrolled
        popup.menu.findItem(R.id.action_config_delete).apply {
            val red = UiKit.themeColor(requireContext(), MaterialR.attr.colorError)
            title = SpannableString(title).apply { setSpan(ForegroundColorSpan(red), 0, length, 0) }
            icon?.mutate()?.setTint(red)
        }
        popup.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_config_edit -> showManualInputDialog(config)
                R.id.action_config_qr -> showQrDialog(config)
                R.id.action_config_refresh -> refreshEnrollment(config)
                R.id.action_config_delete -> confirmDelete(config)
            }
            true
        }
        popup.show()
    }

    private fun confirmDelete(config: VpnConfig) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.delete_config_title)
            .setMessage(getString(R.string.delete_config_message, config.name))
            .setPositiveButton(R.string.delete) { _, _ ->
                configManager.deleteConfig(config.id)
                EnrollmentManager(requireContext()).forget(config.id)
                loadConfigs()
                showSnackbar(getString(R.string.config_deleted, config.name))
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Re-check an enrolled config right now, ignoring the once-a-minute throttle. */
    private fun refreshEnrollment(config: VpnConfig) {
        val appContext = requireContext().applicationContext
        EnrollmentManager.runAsync({ EnrollmentManager(appContext).sync(config.id, force = true) }) { outcome ->
            if (!isAdded) return@runAsync
            loadConfigs()
            when (outcome?.result) {
                is EnrollResult.Success -> showSnackbar(getString(R.string.config_refreshed))
                is EnrollResult.Revoked -> EnrollmentUi.showSyncOutcomes(requireActivity(), listOf(outcome))
                is EnrollResult.RateLimited -> showSnackbar(getString(R.string.enroll_rate_limited))
                else -> showSnackbar(getString(R.string.enroll_server_unavailable))
            }
        }
    }

    /** Show the config as a QR code in the desktop client's format (TOML → Base64 → URL-encoded). */
    private fun showQrDialog(config: VpnConfig) {
        val payload = URLEncoder.encode(
            Base64.encodeToString(config.rawToml.toByteArray(Charsets.UTF_8), Base64.NO_WRAP), "UTF-8"
        )
        val sizePx = (280 * resources.displayMetrics.density).toInt()
        val bitmap = runCatching { renderQr(payload, sizePx) }.getOrNull()
        if (bitmap == null) {
            showSnackbar(getString(R.string.config_qr_too_big))
            return
        }
        val image = ImageView(requireContext()).apply {
            setImageBitmap(bitmap)
            contentDescription = getString(R.string.config_action_qr)
            val pad = (16 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
        }
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(config.name)
            .setMessage(R.string.config_qr_warning)
            .setView(image)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun renderQr(text: String, sizePx: Int): Bitmap {
        val matrix = QRCodeWriter().encode(
            text, BarcodeFormat.QR_CODE, sizePx, sizePx, mapOf(EncodeHintType.MARGIN to 1)
        )
        val pixels = IntArray(sizePx * sizePx) { i ->
            if (matrix[i % sizePx, i / sizePx]) Color.BLACK else Color.WHITE
        }
        return Bitmap.createBitmap(pixels, sizePx, sizePx, Bitmap.Config.ARGB_8888)
    }

    // ── Add options ────────────────────────────────────────────────────────────

    /** Bottom sheet: dashboard link and QR code up front, the rest as rows. */
    private fun showAddOptions() {
        val dialog = BottomSheetDialog(requireContext())
        val sheet = layoutInflater.inflate(R.layout.sheet_add_config, null)
        fun action(block: () -> Unit) = View.OnClickListener {
            dialog.dismiss()
            block()
        }
        sheet.findViewById<View>(R.id.addByLink).setOnClickListener(action {
            EnrollmentUi.promptForLink(requireActivity()) { loadConfigs() }
        })
        sheet.findViewById<View>(R.id.addByQr).setOnClickListener(action { openQrScanner() })
        bindAddRow(sheet.findViewById(R.id.addConstructor), R.drawable.ic_ft_wand,
            R.string.add_constructor_short, R.string.add_constructor_sub, action { showConstructorDialog() })
        bindAddRow(sheet.findViewById(R.id.addManual), R.drawable.ic_ft_code,
            R.string.add_manually_short, R.string.add_manually_sub, action { showManualInputDialog(null) })
        bindAddRow(sheet.findViewById(R.id.addFile), R.drawable.ic_ft_file,
            R.string.import_from_file_short, R.string.import_from_file_sub, action { fileLauncher.launch("*/*") })
        dialog.setContentView(sheet)
        dialog.show()
    }

    private fun bindAddRow(row: View, iconRes: Int, titleRes: Int, subRes: Int, onClick: View.OnClickListener) {
        row.findViewById<ImageView>(R.id.addRowIcon).setImageResource(iconRes)
        row.findViewById<TextView>(R.id.addRowTitle).setText(titleRes)
        row.findViewById<TextView>(R.id.addRowSub).setText(subRes)
        row.contentDescription = getString(titleRes)
        row.setOnClickListener(onClick)
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

    /** Enter a TOML config by hand, or edit [existing] in place. */
    private fun showManualInputDialog(existing: VpnConfig?) {
        val dialogView = LayoutInflater.from(requireContext())
            .inflate(R.layout.dialog_add_config, null)
        val nameInput  = dialogView.findViewById<TextInputEditText>(R.id.configNameInput)
        val tomlInput  = dialogView.findViewById<TextInputEditText>(R.id.configInput)
        existing?.let {
            nameInput.setText(it.name)
            tomlInput.setText(it.rawToml)
        }

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(if (existing != null) R.string.config_action_edit else R.string.add_manually)
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
                    VpnConfig(id = existing?.id ?: System.currentTimeMillis().toString(), name = name, rawToml = toml)
                )
                loadConfigs()
                showSnackbar(getString(if (existing != null) R.string.config_saved else R.string.qr_imported, name))
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ── Config constructor ──────────────────────────────────────────────────────

    private fun showConstructorDialog() {
        val v = LayoutInflater.from(requireContext())
            .inflate(R.layout.dialog_config_constructor, null)

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.constructor_title)
            .setView(v)
            .setPositiveButton(R.string.ctor_create, null) // overridden below to keep dialog open on error
            .setNegativeButton(android.R.string.cancel, null)
            .show()
            .apply {
                getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    val host = textOf(v, R.id.ctorHost)
                    val addresses = textOf(v, R.id.ctorAddresses)
                    val username = textOf(v, R.id.ctorUsername)
                    val password = textOf(v, R.id.ctorPassword)
                    if (host.isBlank() || addresses.isBlank() || username.isBlank() || password.isBlank()) {
                        showSnackbar(getString(R.string.ctor_required_error))
                        return@setOnClickListener
                    }
                    val toml = buildConstructorToml(v, host, addresses, username, password)
                    val customName = textOf(v, R.id.ctorName)
                    val name = customName.ifBlank { host }
                    configManager.saveConfig(
                        VpnConfig(id = System.currentTimeMillis().toString(), name = name, rawToml = toml)
                    )
                    loadConfigs()
                    showSnackbar(getString(R.string.ctor_created, name))
                    dismiss()
                }
            }
    }

    private fun textOf(root: View, id: Int): String =
        root.findViewById<TextInputEditText>(id).text?.toString()?.trim().orEmpty()

    /** Assemble a TrustTunnel TOML from the constructor form. */
    private fun buildConstructorToml(
        root: View, host: String, addresses: String, username: String, password: String
    ): String {
        fun quotedList(raw: String, splitOn: Regex): String =
            raw.split(splitOn)
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .joinToString(", ") { "\"$it\"" }

        val sni = textOf(root, R.id.ctorSni)
        val dnsList = quotedList(textOf(root, R.id.ctorDns), Regex("[\\r\\n,]+"))
            .ifBlank { "\"1.1.1.1\", \"8.8.8.8\"" }
        val exclList = quotedList(textOf(root, R.id.ctorExclusions), Regex("[\\r\\n]+"))
        val addrList = quotedList(addresses, Regex("[,;\\s]+"))

        val selective = root.findViewById<RadioGroup>(R.id.ctorMode)
            .checkedRadioButtonId == R.id.ctorModeSelective
        val killswitch = root.findViewById<MaterialSwitch>(R.id.ctorKillswitch).isChecked
        val postQuantum = root.findViewById<MaterialSwitch>(R.id.ctorPostQuantum).isChecked
        val skipVerify = root.findViewById<MaterialSwitch>(R.id.ctorSkipVerification).isChecked

        return buildString {
            appendLine("loglevel = \"info\"")
            appendLine("vpn_mode = \"${if (selective) "selective" else "general"}\"")
            appendLine("killswitch_enabled = $killswitch")
            appendLine("post_quantum_group_enabled = $postQuantum")
            appendLine("exclusions = [$exclList]")
            appendLine("dns_upstreams = [$dnsList]")
            appendLine()
            appendLine("[endpoint]")
            appendLine("hostname = \"$host\"")
            appendLine("addresses = [$addrList]")
            appendLine("username = \"$username\"")
            appendLine("password = \"$password\"")
            if (sni.isNotBlank()) appendLine("custom_sni = \"$sni\"")
            appendLine("skip_verification = $skipVerify")
        }
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
    private val items: List<VpnConfig>,
    private val activeId: String?,
    /** Badge text for configs enrolled by a dashboard link, keyed by config id. */
    private val enrollmentLabels: Map<String, String>,
    private val onSelect: (VpnConfig) -> Unit,
    private val onMore: (View, VpnConfig) -> Unit
) : RecyclerView.Adapter<ConfigAdapter.VH>() {

    class VH(view: View) : RecyclerView.ViewHolder(view) {
        val card: MaterialCardView = view as MaterialCardView
        val name: TextView = view.findViewById(R.id.configName)
        val active: TextView = view.findViewById(R.id.configActive)
        val address: TextView = view.findViewById(R.id.configAddress)
        val enrollment: TextView = view.findViewById(R.id.configEnrollment)
        val more: MaterialButton = view.findViewById(R.id.configMore)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(LayoutInflater.from(parent.context).inflate(R.layout.item_config, parent, false))

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = items[position]
        val ctx = holder.itemView.context
        val selected = item.id == activeId
        holder.name.text = item.name
        holder.address.text = UiKit.endpointSummary(item)
        holder.active.visibility = if (selected) View.VISIBLE else View.GONE
        androidx.core.widget.TextViewCompat.setCompoundDrawableTintList(
            holder.active, ColorStateList.valueOf(UiKit.themeColor(ctx, MaterialR.attr.colorPrimary))
        )
        holder.card.strokeColor = UiKit.themeColor(
            ctx, if (selected) MaterialR.attr.colorPrimary else MaterialR.attr.colorOutlineVariant
        )
        holder.card.setCardBackgroundColor(UiKit.themeColor(
            ctx, if (selected) MaterialR.attr.colorSurfaceContainerHigh else MaterialR.attr.colorSurfaceContainerLowest
        ))
        holder.card.contentDescription =
            if (selected) ctx.getString(R.string.config_active_desc, item.name) else item.name

        val label = enrollmentLabels[item.id]
        holder.enrollment.visibility = if (label != null) View.VISIBLE else View.GONE
        holder.enrollment.text = label
        androidx.core.widget.TextViewCompat.setCompoundDrawableTintList(
            holder.enrollment, ColorStateList.valueOf(UiKit.themeColor(ctx, MaterialR.attr.colorOnPrimaryContainer))
        )

        holder.card.setOnClickListener { onSelect(item) }
        holder.more.contentDescription = ctx.getString(R.string.config_actions_desc, item.name)
        holder.more.setOnClickListener { onMore(it, item) }
    }

    override fun getItemCount() = items.size
}
