package me.pnsrc.firetunnel

import android.app.Activity
import android.os.Handler
import android.os.Looper
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.progressindicator.LinearProgressIndicator
import me.pnsrc.firetunnel.data.ReleaseInfo
import me.pnsrc.firetunnel.data.StatsFormat
import me.pnsrc.firetunnel.data.UpdateCheck
import me.pnsrc.firetunnel.data.UpdateManager
import java.io.File
import java.io.IOException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Dialogs for checking, downloading and installing app updates. */
object UpdateUi {

    private const val MAX_NOTES_CHARS = 1_500

    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "app-update") }
    private val mainHandler = Handler(Looper.getMainLooper())

    /** Daily background check on launch: only speaks up when an update is available. */
    fun checkIfDue(activity: Activity) {
        val manager = UpdateManager(activity)
        if (!manager.isAutoCheckDue()) return
        executor.execute {
            val result = manager.check()
            mainHandler.post {
                if (result is UpdateCheck.Available && !manager.isSkipped(result.release) && activity.isAlive()) {
                    showAvailable(activity, result.release, allowSkip = true)
                }
            }
        }
    }

    /** Check right now (Settings button) and always report the outcome. */
    fun checkNow(activity: Activity, onDone: () -> Unit = {}) {
        val manager = UpdateManager(activity)
        executor.execute {
            val result = manager.check()
            mainHandler.post {
                onDone()
                if (!activity.isAlive()) return@post
                when (result) {
                    is UpdateCheck.Available -> showAvailable(activity, result.release, allowSkip = false)
                    is UpdateCheck.UpToDate -> Toast.makeText(
                        activity, activity.getString(R.string.update_up_to_date, manager.currentVersionName),
                        Toast.LENGTH_SHORT
                    ).show()
                    is UpdateCheck.Failed -> Toast.makeText(
                        activity, R.string.update_check_failed, Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }

    private fun showAvailable(activity: Activity, release: ReleaseInfo, allowSkip: Boolean) {
        val manager = UpdateManager(activity)
        val notes = release.notes.let { if (it.length > MAX_NOTES_CHARS) it.take(MAX_NOTES_CHARS) + "…" else it }
        val size = if (release.apkSize > 0) StatsFormat.bytes(release.apkSize) else null
        val message = buildString {
            append(activity.getString(R.string.update_versions, manager.currentVersionName, release.version.toString()))
            size?.let { append('\n').append(activity.getString(R.string.update_size, it)) }
            if (manager.isDebugBuild) append("\n\n").append(activity.getString(R.string.update_debug_warning))
            if (notes.isNotEmpty()) append("\n\n").append(notes)
        }
        MaterialAlertDialogBuilder(activity)
            .setTitle(activity.getString(R.string.update_available_title, release.version.toString()))
            .setMessage(message)
            .setPositiveButton(R.string.update_download) { _, _ -> download(activity, release) }
            .setNegativeButton(R.string.update_later, null)
            .apply {
                if (allowSkip) setNeutralButton(R.string.update_skip) { _, _ -> manager.skip(release) }
            }
            .show()
    }

    private fun download(activity: Activity, release: ReleaseInfo) {
        val cancelled = AtomicBoolean(false)
        val progress = LinearProgressIndicator(activity).apply { isIndeterminate = true }
        val label = TextView(activity).apply {
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
        }
        val pad = (24 * activity.resources.displayMetrics.density).toInt()
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad / 2, pad, 0)
            addView(progress)
            addView(label)
        }
        val dialog = MaterialAlertDialogBuilder(activity)
            .setTitle(activity.getString(R.string.update_downloading, release.version.toString()))
            .setView(content)
            .setCancelable(false)
            .setNegativeButton(android.R.string.cancel) { _, _ -> cancelled.set(true) }
            .show()

        val manager = UpdateManager(activity)
        var lastUiUpdate = 0L
        executor.execute {
            val result = runCatching {
                manager.download(release, cancelled::get) { done, total ->
                    val now = System.currentTimeMillis()
                    if (now - lastUiUpdate < 100 && done != total) return@download
                    lastUiUpdate = now
                    mainHandler.post {
                        if (total > 0) {
                            progress.isIndeterminate = false
                            progress.setProgressCompat((done * 100 / total).toInt(), true)
                            label.text = "${StatsFormat.bytes(done)} / ${StatsFormat.bytes(total)}"
                        } else {
                            label.text = StatsFormat.bytes(done)
                        }
                    }
                }
            }
            mainHandler.post {
                runCatching { dialog.dismiss() }
                if (!activity.isAlive() || cancelled.get()) return@post
                result
                    .onSuccess { apk -> promptInstall(activity, apk) }
                    .onFailure { e ->
                        val reason = if (e is IOException) e.message else e.javaClass.simpleName
                        MaterialAlertDialogBuilder(activity)
                            .setTitle(R.string.update_failed_title)
                            .setMessage(activity.getString(R.string.update_failed_message, reason ?: ""))
                            .setPositiveButton(android.R.string.ok, null)
                            .show()
                    }
            }
        }
    }

    /**
     * Ask the system to install [apk]. Installing needs the per-app "Install unknown
     * apps" switch; the dialog stays open while the user turns it on in Settings.
     */
    private fun promptInstall(activity: Activity, apk: File) {
        val manager = UpdateManager(activity)
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.update_ready_title)
            .setMessage(R.string.update_ready_message)
            .setPositiveButton(R.string.update_install, null) // overridden to keep the dialog open
            .setNegativeButton(R.string.update_later, null)
            .show()
            .apply {
                getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    if (manager.canInstall()) {
                        dismiss()
                        activity.startActivity(manager.installIntent(apk))
                    } else {
                        Toast.makeText(activity, R.string.update_allow_install, Toast.LENGTH_LONG).show()
                        activity.startActivity(manager.installPermissionIntent())
                    }
                }
            }
    }

    private fun Activity.isAlive() = !isFinishing && !isDestroyed
}
