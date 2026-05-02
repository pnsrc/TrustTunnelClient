package com.trusttunnel.android

import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.materialswitch.MaterialSwitch

class SettingsActivity : AppCompatActivity() {
    private lateinit var prefs: SharedPreferences
    private lateinit var killswitchCheck: MaterialSwitch
    private lateinit var notificationsCheck: MaterialSwitch
    private lateinit var logLevelSpinner: Spinner
    private lateinit var saveButton: MaterialButton
    private lateinit var viewLogsCard: MaterialCardView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        prefs = getSharedPreferences("settings", MODE_PRIVATE)
        initializeViews()
        loadSettings()
        setupListeners()
    }

    private fun initializeViews() {
        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        killswitchCheck    = findViewById(R.id.killswitchCheck)
        notificationsCheck = findViewById(R.id.notificationsCheck)
        logLevelSpinner    = findViewById(R.id.logLevelSpinner)
        saveButton         = findViewById(R.id.saveButton)
        viewLogsCard       = findViewById(R.id.viewLogsCard)
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
        viewLogsCard.setOnClickListener {
            startActivity(Intent(this, LogActivity::class.java))
        }
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
