package com.trusttunnel.android

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import java.io.File

/**
 * Simple log viewer that reads the logback-android rolling log file and
 * displays the last 500 lines in a scrollable text view.
 *
 * The log file is written by logback to  [filesDir]/logs/trusttunnel.log
 * as configured in assets/logback.xml.
 */
class LogActivity : AppCompatActivity() {

    private lateinit var logTextView: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var refreshButton: MaterialButton
    private lateinit var copyButton: MaterialButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_logs)

        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        logTextView    = findViewById(R.id.logTextView)
        scrollView     = findViewById(R.id.logScrollView)
        refreshButton  = findViewById(R.id.refreshButton)
        copyButton     = findViewById(R.id.copyButton)

        refreshButton.setOnClickListener { loadLogs() }
        copyButton.setOnClickListener    { copyLogs() }

        loadLogs()
    }

    // ── Log loading ───────────────────────────────────────────────────────────

    private fun logFile(): File = File(filesDir, "logs/trusttunnel.log")

    private fun loadLogs() {
        val file = logFile()
        val text = when {
            !file.exists() -> getString(R.string.logs_empty)
            else -> {
                try {
                    // Read up to 500 lines from the end to avoid OOM on large files
                    val lines = file.readLines(Charsets.UTF_8)
                    val tail = if (lines.size > 500) lines.takeLast(500) else lines
                    if (tail.isEmpty()) getString(R.string.logs_empty)
                    else tail.joinToString("\n")
                } catch (e: Exception) {
                    getString(R.string.logs_read_error, e.message)
                }
            }
        }
        logTextView.text = text
        // Scroll to bottom to show the latest entries
        scrollView.post { scrollView.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    // ── Copy to clipboard ─────────────────────────────────────────────────────

    private fun copyLogs() {
        val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        val content = logTextView.text?.toString()
        if (content.isNullOrBlank()) {
            Toast.makeText(this, R.string.logs_empty, Toast.LENGTH_SHORT).show()
            return
        }
        cm.setPrimaryClip(ClipData.newPlainText("TrustTunnel logs", content))
        Toast.makeText(this, R.string.logs_copied, Toast.LENGTH_SHORT).show()
    }
}
