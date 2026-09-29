package me.pnsrc.firetunnel

import android.app.Activity
import android.content.Context
import android.view.LayoutInflater
import android.widget.FrameLayout
import android.widget.Toast
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.android.material.textfield.TextInputEditText
import me.pnsrc.firetunnel.data.EnrollOutcome
import me.pnsrc.firetunnel.data.EnrollResult
import me.pnsrc.firetunnel.data.EnrollmentManager
import me.pnsrc.firetunnel.data.EnrollmentProtocol

/** Dialogs shared by every entry point to device enrollment (deeplink, paste, QR). */
object EnrollmentUi {

    /** Ask the user to paste an enrollment link, then enroll with it. */
    fun promptForLink(activity: Activity, onEnrolled: () -> Unit) {
        val view = LayoutInflater.from(activity).inflate(R.layout.dialog_enroll_link, null)
        val input = view.findViewById<TextInputEditText>(R.id.enrollLinkInput)
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.enroll_title)
            .setView(view)
            .setPositiveButton(R.string.enroll_connect) { _, _ ->
                val url = EnrollmentProtocol.parseEnrollLink(input.text?.toString().orEmpty())
                if (url == null) showInvalidLink(activity)
                else enroll(activity, url, onEnrolled)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Handle a raw link from a deeplink or QR code: validate, confirm, enroll. */
    fun confirmAndEnroll(activity: Activity, rawLink: String, onEnrolled: () -> Unit) {
        val url = EnrollmentProtocol.parseEnrollLink(rawLink)
        if (url == null) {
            showInvalidLink(activity)
            return
        }
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.enroll_title)
            .setMessage(activity.getString(R.string.enroll_confirm, EnrollmentProtocol.displayHost(url)))
            .setPositiveButton(R.string.enroll_connect) { _, _ -> enroll(activity, url, onEnrolled) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Show the outcome of a background sync. Only revocations are surfaced:
     * temporary failures must not bother the user while the old config still works.
     */
    fun showSyncOutcomes(activity: Activity, outcomes: List<EnrollOutcome>) {
        if (!activity.isAlive()) return
        outcomes.filter { it.result is EnrollResult.Revoked }.forEach { showOutcome(activity, it) }
    }

    private fun enroll(activity: Activity, url: String, onEnrolled: () -> Unit) {
        val progress = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.enroll_title)
            .setMessage(R.string.enroll_in_progress)
            .setView(FrameLayout(activity).apply {
                val pad = (24 * resources.displayMetrics.density).toInt()
                setPadding(pad, 0, pad, 0)
                addView(LinearProgressIndicator(activity).apply { isIndeterminate = true })
            })
            .setCancelable(false)
            .show()

        val appContext = activity.applicationContext
        EnrollmentManager.runAsync({ EnrollmentManager(appContext).enroll(url) }) { outcome ->
            runCatching { progress.dismiss() }
            if (!activity.isAlive()) return@runAsync
            showOutcome(activity, outcome)
            if (outcome.result is EnrollResult.Success) onEnrolled()
        }
    }

    private fun showOutcome(activity: Activity, outcome: EnrollOutcome) {
        when (val r = outcome.result) {
            is EnrollResult.Success -> Toast.makeText(
                activity, activity.getString(R.string.enroll_success, outcome.configName), Toast.LENGTH_LONG
            ).show()
            is EnrollResult.Revoked -> showMessage(
                activity,
                activity.getString(R.string.enroll_revoked_title, outcome.configName),
                revokedMessage(activity, r)
            )
            is EnrollResult.ClientError -> showMessage(
                activity,
                activity.getString(R.string.enroll_failed_title),
                r.message ?: activity.getString(R.string.enroll_http_error, r.httpCode)
            )
            is EnrollResult.RateLimited -> showMessage(
                activity,
                activity.getString(R.string.enroll_failed_title),
                activity.getString(R.string.enroll_rate_limited)
            )
            is EnrollResult.TemporaryFailure -> showMessage(
                activity,
                activity.getString(R.string.enroll_failed_title),
                activity.getString(R.string.enroll_server_unavailable)
            )
        }
    }

    private fun revokedMessage(context: Context, r: EnrollResult.Revoked): String {
        val fallback = when (r.error) {
            EnrollmentProtocol.ERROR_DEVICE_REVOKED -> R.string.enroll_device_revoked
            EnrollmentProtocol.ERROR_NO_ACCESS -> R.string.enroll_no_access
            EnrollmentProtocol.ERROR_UNKNOWN_LINK -> R.string.enroll_unknown_link
            else -> if (r.httpCode == 404) R.string.enroll_unknown_link else R.string.enroll_no_access
        }
        val text = r.message ?: context.getString(fallback)
        // A 404 means the link was reissued: always tell the user where to get a new one.
        return if (r.httpCode == 404 && r.message != null) {
            text + "\n\n" + context.getString(R.string.enroll_unknown_link)
        } else {
            text
        }
    }

    private fun showInvalidLink(activity: Activity) =
        showMessage(activity, activity.getString(R.string.enroll_failed_title),
            activity.getString(R.string.enroll_invalid_link))

    private fun showMessage(activity: Activity, title: String, message: String) {
        if (!activity.isAlive()) return
        MaterialAlertDialogBuilder(activity)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun Activity.isAlive() = !isFinishing && !isDestroyed
}
