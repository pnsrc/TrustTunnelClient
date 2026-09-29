package me.pnsrc.firetunnel

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import me.pnsrc.firetunnel.data.EnrollOutcome
import me.pnsrc.firetunnel.data.EnrollResult
import me.pnsrc.firetunnel.data.EnrollmentManager
import java.util.concurrent.TimeUnit

/**
 * Periodic re-check of every enrollment link, so a device revoked in the dashboard
 * loses its config (and the VPN) without waiting for the app to be reopened.
 * WorkManager also runs a missed check soon after the device wakes up.
 */
class EnrollmentCheckWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    companion object {
        private const val WORK_NAME = "enrollment-check"
        private const val INTERVAL_MINUTES = 30L
        private const val CHANNEL_ID = "firetunnel_access"

        /** Schedule the periodic check; a no-op if it is already scheduled. */
        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<EnrollmentCheckWorker>(INTERVAL_MINUTES, TimeUnit.MINUTES)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }

    override fun doWork(): Result {
        val outcomes = EnrollmentManager.runSerialized {
            val manager = EnrollmentManager(applicationContext)
            if (manager.enrolledConfigIds().isEmpty()) emptyList() else manager.syncAll()
        }
        outcomes.filter { it.result is EnrollResult.Revoked }.forEach(::notifyRevoked)
        // Temporary failures are not retried here: the next period is soon enough.
        return Result.success()
    }

    private fun notifyRevoked(outcome: EnrollOutcome) {
        val ctx = applicationContext
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
            && ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
        ) return

        val nm = ctx.getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, ctx.getString(R.string.access_channel_name),
                    NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val open = PendingIntent.getActivity(
            ctx, 0, Intent(ctx, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val text = EnrollmentUi.revokedMessage(ctx, outcome.result as EnrollResult.Revoked)
        val notification = NotificationCompat.Builder(ctx, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentTitle(ctx.getString(R.string.enroll_revoked_title, outcome.configName))
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(ctx).notify(outcome.configId.hashCode(), notification)
    }
}
