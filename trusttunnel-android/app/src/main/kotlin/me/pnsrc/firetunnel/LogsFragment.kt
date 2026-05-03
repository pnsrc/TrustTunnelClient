package me.pnsrc.firetunnel

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import java.io.File

class LogsFragment : Fragment() {

    private lateinit var logTextView: TextView
    private lateinit var scrollView: ScrollView

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_logs, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        logTextView = view.findViewById(R.id.logTextView)
        scrollView  = view.findViewById(R.id.logScrollView)

        view.findViewById<MaterialButton>(R.id.refreshButton).setOnClickListener { loadLogs() }
        view.findViewById<MaterialButton>(R.id.copyButton).setOnClickListener    { copyLogs() }

        loadLogs()
    }

    override fun onResume() {
        super.onResume()
        loadLogs()
    }

    // ── Log loading ───────────────────────────────────────────────────────────

    private fun logFile(): File = File(requireContext().filesDir, "logs/trusttunnel.log")

    private fun loadLogs() {
        if (!isAdded) return
        val file = logFile()
        val text = when {
            !file.exists() -> getString(R.string.logs_empty)
            else -> runCatching {
                val lines = file.readLines(Charsets.UTF_8)
                val tail  = if (lines.size > 500) lines.takeLast(500) else lines
                if (tail.isEmpty()) getString(R.string.logs_empty)
                else tail.joinToString("\n")
            }.getOrElse { getString(R.string.logs_read_error, it.message) }
        }
        logTextView.text = text
        scrollView.post { scrollView.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    // ── Clipboard copy ─────────────────────────────────────────────────────────

    private fun copyLogs() {
        val ctx     = requireContext()
        val content = logTextView.text?.toString()
        if (content.isNullOrBlank()) {
            Toast.makeText(ctx, R.string.logs_empty, Toast.LENGTH_SHORT).show()
            return
        }
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("FireTunnel logs", content))
        Toast.makeText(ctx, R.string.logs_copied, Toast.LENGTH_SHORT).show()
    }
}
