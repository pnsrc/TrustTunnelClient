package com.trusttunnel.android

import android.content.SharedPreferences
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity

class SettingsActivity : AppCompatActivity() {
    private lateinit var prefs: SharedPreferences
    private lateinit var killswitchCheck: CheckBox
    private lateinit var notificationsCheck: CheckBox
    private lateinit var logLevelSpinner: Spinner
    private lateinit var saveButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        prefs = getSharedPreferences("settings", MODE_PRIVATE)
        initializeViews()
        loadSettings()
        setupListeners()
    }

    private fun initializeViews() {
        val backButton: Button = findViewById(R.id.backButton)
        killswitchCheck = findViewById(R.id.killswitchCheck)
        notificationsCheck = findViewById(R.id.notificationsCheck)
        logLevelSpinner = findViewById(R.id.logLevelSpinner)
        saveButton = findViewById(R.id.saveButton)

        backButton.setOnClickListener { finish() }
    }

    private fun loadSettings() {
        killswitchCheck.isChecked = prefs.getBoolean("killswitch_enabled", false)
        notificationsCheck.isChecked = prefs.getBoolean("notifications_enabled", true)

        val logLevels = arrayOf("Debug", "Info", "Warning", "Error")
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, logLevels)
        logLevelSpinner.adapter = adapter

        val savedLevel = prefs.getString("log_level", "Info")
        val index = logLevels.indexOf(savedLevel)
        logLevelSpinner.setSelection(if (index >= 0) index else 1)
    }

    private fun setupListeners() {
        saveButton.setOnClickListener { saveSettings() }
    }

    private fun saveSettings() {
        prefs.edit().apply {
            putBoolean("killswitch_enabled", killswitchCheck.isChecked)
            putBoolean("notifications_enabled", notificationsCheck.isChecked)
            putString(
                "log_level",
                logLevelSpinner.selectedItem.toString()
            )
            apply()
        }

        Toast.makeText(this, "Settings saved", Toast.LENGTH_SHORT).show()
        finish()
    }
}
