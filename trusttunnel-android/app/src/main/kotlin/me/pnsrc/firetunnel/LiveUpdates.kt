package me.pnsrc.firetunnel

import android.app.Notification
import android.os.Build
import android.util.Log

/**
 * Android 16 Live Updates: an ongoing notification the system may promote to a
 * status bar chip and the top of the shade. The APIs are from API 36; the app
 * compiles against API 35, so they are called reflectively and only on 36+.
 * The system still decides: the user can turn promotion off per app, and a
 * notification with custom views or colorization is never promoted.
 */
object LiveUpdates {
    const val MIN_SDK = 36
    private const val TAG = "LiveUpdates"

    /** Ask for promotion (`Notification.Builder.setRequestPromotedOngoing(true)`). */
    fun requestPromotion(builder: Notification.Builder) {
        if (Build.VERSION.SDK_INT < MIN_SDK) return
        runCatching {
            Notification.Builder::class.java
                .getMethod("setRequestPromotedOngoing", Boolean::class.javaPrimitiveType)
                .invoke(builder, true)
        }.onFailure { Log.w(TAG, "setRequestPromotedOngoing unavailable", it) }
    }

    /** Set the chip's short text (`setShortCriticalText`); a chronometer shows when this is unset. */
    fun setChipText(builder: Notification.Builder, text: String) {
        if (Build.VERSION.SDK_INT < MIN_SDK) return
        runCatching {
            Notification.Builder::class.java
                .getMethod("setShortCriticalText", String::class.java)
                .invoke(builder, text)
        }.onFailure { Log.w(TAG, "setShortCriticalText unavailable", it) }
    }
}
