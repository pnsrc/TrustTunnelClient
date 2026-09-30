package me.pnsrc.firetunnel

import android.content.Intent
import android.graphics.Rect
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.NestedScrollView
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.button.MaterialButtonToggleGroup
import com.google.android.material.chip.ChipGroup
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import me.pnsrc.firetunnel.data.ConfigBuilder
import me.pnsrc.firetunnel.data.ConfigBuilder.Problem
import me.pnsrc.firetunnel.data.ConfigForm
import me.pnsrc.firetunnel.data.ConfigManager
import me.pnsrc.firetunnel.data.VpnConfig

/**
 * Step-by-step config constructor: server, login, protocol and DNS up front,
 * rarely needed options folded under "Advanced". Every field explains itself;
 * errors are shown on the field. Routing (exclusions, modes) lives in the Rules tab.
 */
class ConfigConstructorActivity : AppCompatActivity() {

    private companion object {
        val DNS_CLOUDFLARE = listOf("1.1.1.1", "1.0.0.1")
        val DNS_GOOGLE = listOf("8.8.8.8", "8.8.4.4")
    }

    private lateinit var antiDpi: SettingRow
    private lateinit var postQuantum: SettingRow
    private lateinit var skipVerify: SettingRow
    private var antiDpiOn = false
    private var postQuantumOn = true
    private var skipVerifyOn = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_config_constructor)

        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        setupProtocol()
        setupDns()
        setupAdvanced()
        clearErrorOnEdit(R.id.ctorServer, R.id.ctorUsername, R.id.ctorPassword, R.id.ctorExtraAddresses)
        findViewById<MaterialButton>(R.id.ctorCreate).setOnClickListener { create() }
    }

    private fun setupProtocol() {
        val hint = findViewById<TextView>(R.id.ctorProtocolHint)
        findViewById<MaterialButtonToggleGroup>(R.id.ctorProtocol).addOnButtonCheckedListener { _, id, checked ->
            if (checked) hint.setText(if (id == R.id.ctorHttp3) R.string.ctor_http3_hint else R.string.ctor_http2_hint)
        }
    }

    private fun setupDns() {
        val hint = findViewById<TextView>(R.id.ctorDnsHint)
        val custom = findViewById<View>(R.id.ctorDnsCustomInputLayout)
        findViewById<ChipGroup>(R.id.ctorDnsChoice).setOnCheckedStateChangeListener { _, ids ->
            val id = ids.firstOrNull()
            custom.visibility = if (id == R.id.ctorDnsCustom) View.VISIBLE else View.GONE
            hint.setText(when (id) {
                R.id.ctorDnsCloudflare -> R.string.ctor_dns_cloudflare_hint
                R.id.ctorDnsGoogle -> R.string.ctor_dns_google_hint
                R.id.ctorDnsCustom -> R.string.ctor_dns_custom_choice_hint
                else -> R.string.ctor_dns_default_hint
            })
        }
        custom.visibility = View.GONE
    }

    private fun setupAdvanced() {
        val toggle = findViewById<MaterialButton>(R.id.ctorAdvancedToggle)
        val panel = findViewById<View>(R.id.ctorAdvanced)
        toggle.setOnClickListener {
            val show = panel.visibility != View.VISIBLE
            panel.visibility = if (show) View.VISIBLE else View.GONE
            toggle.setText(if (show) R.string.ctor_hide_advanced else R.string.ctor_show_advanced)
        }
        toggle.iconGravity = MaterialButton.ICON_GRAVITY_END

        antiDpi = SettingRow(findViewById(R.id.ctorAntiDpi))
            .bind(R.drawable.ic_ft_wand, getString(R.string.ctor_anti_dpi), getString(R.string.ctor_anti_dpi_sub))
            .asSwitch(antiDpiOn) { antiDpiOn = it }
        postQuantum = SettingRow(findViewById(R.id.ctorPostQuantum))
            .bind(R.drawable.ic_ft_lock, getString(R.string.ctor_post_quantum), getString(R.string.ctor_post_quantum_sub))
            .asSwitch(postQuantumOn) { postQuantumOn = it }
        skipVerify = SettingRow(findViewById(R.id.ctorSkipVerify))
            .bind(R.drawable.ic_ft_info, getString(R.string.ctor_skip_verification), getString(R.string.ctor_skip_verification_sub))
            .asSwitch(skipVerifyOn) { skipVerifyOn = it }
    }

    private fun text(id: Int): String = findViewById<TextInputEditText>(id).text?.toString().orEmpty()

    private fun layoutOf(inputId: Int): TextInputLayout? {
        var parent = findViewById<View>(inputId).parent
        while (parent != null && parent !is TextInputLayout) parent = parent.parent
        return parent as? TextInputLayout
    }

    private fun clearErrorOnEdit(vararg ids: Int) {
        for (id in ids) findViewById<TextInputEditText>(id).doAfterTextChanged { layoutOf(id)?.error = null }
    }

    private fun form(): ConfigForm {
        val dns = when (findViewById<ChipGroup>(R.id.ctorDnsChoice).checkedChipId) {
            R.id.ctorDnsCloudflare -> DNS_CLOUDFLARE
            R.id.ctorDnsGoogle -> DNS_GOOGLE
            R.id.ctorDnsCustom -> ConfigBuilder.splitList(text(R.id.ctorDnsCustomInput))
            else -> emptyList()
        }
        return ConfigForm(
            server = text(R.id.ctorServer).trim(),
            extraAddresses = ConfigBuilder.splitList(text(R.id.ctorExtraAddresses)),
            username = text(R.id.ctorUsername),
            password = text(R.id.ctorPassword),
            http3 = findViewById<MaterialButtonToggleGroup>(R.id.ctorProtocol).checkedButtonId == R.id.ctorHttp3,
            dnsUpstreams = dns,
            customSni = text(R.id.ctorSni),
            antiDpi = antiDpiOn,
            postQuantum = postQuantumOn,
            skipVerification = skipVerifyOn
        )
    }

    private fun create() {
        val form = form()
        val problems = ConfigBuilder.validate(form)
        if (problems.isNotEmpty()) {
            val fields = listOf(
                Problem.SERVER to (R.id.ctorServer to R.string.ctor_error_server),
                Problem.USERNAME to (R.id.ctorUsername to R.string.ctor_error_username),
                Problem.PASSWORD to (R.id.ctorPassword to R.string.ctor_error_password),
                Problem.EXTRA_ADDRESS to (R.id.ctorExtraAddresses to R.string.ctor_error_extra)
            )
            var first: View? = null
            for ((problem, field) in fields) {
                if (problem !in problems) continue
                val (inputId, messageRes) = field
                layoutOf(inputId)?.error = getString(messageRes)
                if (first == null) first = layoutOf(inputId)
            }
            if (Problem.EXTRA_ADDRESS in problems) findViewById<View>(R.id.ctorAdvanced).visibility = View.VISIBLE
            first?.let { target ->
                val scroll = findViewById<NestedScrollView>(R.id.ctorScroll)
                scroll.post {
                    val rect = Rect()
                    target.getDrawingRect(rect)
                    scroll.offsetDescendantRectToMyCoords(target, rect)
                    scroll.smoothScrollTo(0, (rect.top - resources.displayMetrics.density * 24).toInt().coerceAtLeast(0))
                }
            }
            return
        }

        val manager = ConfigManager(this)
        val hadConfigs = manager.getConfigs().isNotEmpty()
        val id = System.currentTimeMillis().toString()
        val name = text(R.id.ctorName).trim().ifBlank { form.server.substringBefore(':') }
        manager.saveConfig(VpnConfig(id = id, name = name, rawToml = ConfigBuilder.build(form)))
        if (!hadConfigs) manager.setActiveConfigId(id)
        setResult(RESULT_OK, Intent().putExtra(EXTRA_CREATED_NAME, name))
        finish()
    }
}

/** Result extra of [ConfigConstructorActivity]: the created config's name. */
const val EXTRA_CREATED_NAME = "created_name"
