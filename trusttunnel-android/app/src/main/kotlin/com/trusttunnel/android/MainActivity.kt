package com.trusttunnel.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.trusttunnel.android.data.ConfigManager
import com.trusttunnel.android.data.VpnConfig

class MainActivity : AppCompatActivity() {
    private lateinit var configManager: ConfigManager
    private lateinit var connectionStatusView: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var connectionButton: Button
    private lateinit var configSpinner: Spinner
    private lateinit var qrButton: Button
    private lateinit var settingsButton: Button
    private lateinit var statsText: TextView
    private var isConnected = false

    companion object {
        private const val QR_PERMISSION_CODE = 100
        private const val CAMERA_PERMISSION_CODE = 101
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        configManager = ConfigManager(this)
        initializeViews()
        setupListeners()
        loadConfigs()
        requestPermissions()
    }

    private fun initializeViews() {
        connectionStatusView = findViewById(R.id.connectionStatusView)
        statusText = findViewById(R.id.statusText)
        connectionButton = findViewById(R.id.connectionButton)
        configSpinner = findViewById(R.id.configSpinner)
        qrButton = findViewById(R.id.qrButton)
        settingsButton = findViewById(R.id.settingsButton)
        statsText = findViewById(R.id.statsText)

        // Apply Claude theme colors
        connectionStatusView.setBackgroundColor(getColor(R.color.claude_purple_dark))
        connectionButton.setBackgroundColor(getColor(R.color.claude_purple))
        qrButton.setBackgroundColor(getColor(R.color.claude_orange))
        settingsButton.setBackgroundColor(getColor(R.color.claude_purple))
    }

    private fun setupListeners() {
        connectionButton.setOnClickListener { toggleConnection() }
        qrButton.setOnClickListener { scanQRCode() }
        settingsButton.setOnClickListener { openSettings() }
    }

    private fun loadConfigs() {
        val configs = configManager.getConfigs()
        val names = configs.map { it.name }

        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, names)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        configSpinner.adapter = adapter
    }

    private fun toggleConnection() {
        isConnected = !isConnected
        updateUI()
    }

    private fun updateUI() {
        if (isConnected) {
            statusText.text = getString(R.string.status_connected)
            statusText.setTextColor(getColor(R.color.claude_green))
            connectionButton.text = getString(R.string.disconnect)
            connectionButton.setBackgroundColor(getColor(R.color.claude_red))
        } else {
            statusText.text = getString(R.string.status_disconnected)
            statusText.setTextColor(getColor(R.color.claude_gray))
            connectionButton.text = getString(R.string.connect)
            connectionButton.setBackgroundColor(getColor(R.color.claude_purple))
        }
    }

    private fun scanQRCode() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.CAMERA),
                CAMERA_PERMISSION_CODE
            )
        } else {
            startActivity(Intent(this, QRScannerActivity::class.java))
        }
    }

    private fun openSettings() {
        startActivity(Intent(this, SettingsActivity::class.java))
    }

    private fun requestPermissions() {
        val permissions = mutableListOf(
            Manifest.permission.INTERNET,
            Manifest.permission.ACCESS_NETWORK_STATE,
            Manifest.permission.CHANGE_NETWORK_STATE
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        val missingPermissions = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missingPermissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(
                this,
                missingPermissions.toTypedArray(),
                QR_PERMISSION_CODE
            )
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        when (requestCode) {
            CAMERA_PERMISSION_CODE -> {
                if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    startActivity(Intent(this, QRScannerActivity::class.java))
                }
            }
        }
    }
}
