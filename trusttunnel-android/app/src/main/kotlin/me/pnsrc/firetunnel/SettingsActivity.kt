package me.pnsrc.firetunnel

import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch

class SettingsActivity : AppCompatActivity() {

    private lateinit var killswitchCheck: MaterialSwitch
    private lateinit var notificationsCheck: MaterialSwitch
    private lateinit var logLevelSpinner: Spinner
    private lateinit var saveButton: MaterialButton

    // About
    private lateinit var tvAboutVersion: TextView
    private lateinit var tvAboutBuild:   TextView
    private lateinit var tvAboutAndroid: TextView
    private lateinit var tvAboutKernel:  TextView
    private lateinit var tvAboutDevice:  TextView
    private lateinit var tvAboutArch:    TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        killswitchCheck    = findViewById(R.id.killswitchCheck)
        notificationsCheck = findViewById(R.id.notificationsCheck)
        logLevelSpinner    = findViewById(R.id.logLevelSpinner)
        saveButton         = findViewById(R.id.saveButton)

        tvAboutVersion = findViewById(R.id.tvAboutVersion)
        tvAboutBuild   = findViewById(R.id.tvAboutBuild)
        tvAboutAndroid = findViewById(R.id.tvAboutAndroid)
        tvAboutKernel  = findViewById(R.id.tvAboutKernel)
        tvAboutDevice  = findViewById(R.id.tvAboutDevice)
        tvAboutArch    = findViewById(R.id.tvAboutArch)

        loadSettings()
        populateAbout()
        saveButton.setOnClickListener { saveSettings() }
    }

    // ── Settings ───────────────────────────────────────────────────────────────

    private fun loadSettings() {
        val prefs = getSharedPreferences("settings", MODE_PRIVATE)
        killswitchCheck.isChecked    = prefs.getBoolean("killswitch_enabled", false)
        notificationsCheck.isChecked = prefs.getBoolean("notifications_enabled", true)

        val logLevels = arrayOf("Debug", "Info", "Warning", "Error")
        logLevelSpinner.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_item, logLevels
        ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
        val saved = prefs.getString("log_level", "Info")
        logLevelSpinner.setSelection(logLevels.indexOf(saved).coerceAtLeast(0))
    }

    private fun saveSettings() {
        getSharedPreferences("settings", MODE_PRIVATE).edit().apply {
            putBoolean("killswitch_enabled",     killswitchCheck.isChecked)
            putBoolean("notifications_enabled",  notificationsCheck.isChecked)
            putString("log_level",               logLevelSpinner.selectedItem.toString())
            apply()
        }
        Toast.makeText(this, R.string.save, Toast.LENGTH_SHORT).show()
        finish()
    }

    // ── About ──────────────────────────────────────────────────────────────────

    private fun populateAbout() {
        // App version
        val pi = runCatching { packageManager.getPackageInfo(packageName, 0) }.getOrNull()
        val versionName = pi?.versionName ?: "—"
        val versionCode = if (pi == null) 0L
                          else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                              pi.longVersionCode
                          else @Suppress("DEPRECATION") pi.versionCode.toLong()
        tvAboutVersion.text = "$versionName ($versionCode)"

        // Build type: debug flag in applicationInfo
        val isDebug = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        tvAboutBuild.text = if (isDebug) "debug" else "release"

        // Android version + API level
        tvAboutAndroid.text = "Android ${Build.VERSION.RELEASE}  (API ${Build.VERSION.SDK_INT})"

        // Linux kernel
        val kernel = System.getProperty("os.version") ?: "—"
        tvAboutKernel.text = kernel

        // Device model
        val manufacturer = Build.MANUFACTURER.replaceFirstChar { it.uppercase() }
        val model = Build.MODEL
        tvAboutDevice.text = if (model.startsWith(manufacturer, ignoreCase = true)) model
                             else "$manufacturer $model"

        // CPU architecture
        tvAboutArch.text = Build.SUPPORTED_ABIS.firstOrNull() ?: Build.CPU_ABI
    }
}
