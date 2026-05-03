package me.pnsrc.firetunnel

import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Spinner
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

        loadSettings()
        saveButton.setOnClickListener { saveSettings() }
    }

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
}
