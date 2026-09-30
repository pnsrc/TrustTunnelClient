package me.pnsrc.firetunnel

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import com.google.android.material.color.DynamicColors
import me.pnsrc.firetunnel.data.AppSettings

/**
 * Base for every screen: applies the chosen colours (wallpaper colours on
 * Android 12+, or one of the palettes) before the layout is inflated, and
 * recreates itself when the appearance was changed on another screen.
 */
open class ThemedActivity : AppCompatActivity() {

    private var appliedAppearance = -1

    override fun onCreate(savedInstanceState: Bundle?) {
        val settings = AppSettings(this)
        if (settings.dynamicColor && DynamicColors.isDynamicColorAvailable()) {
            DynamicColors.applyToActivityIfAvailable(this)
        } else {
            theme.applyStyle(paletteOverlay(settings.palette), true)
        }
        appliedAppearance = settings.appearanceVersion
        super.onCreate(savedInstanceState)
    }

    override fun onResume() {
        super.onResume()
        if (AppSettings(this).appearanceVersion != appliedAppearance) recreate()
    }

    companion object {
        fun paletteOverlay(palette: String): Int = when (palette) {
            "ocean" -> R.style.ThemeOverlay_FireTunnel_Ocean
            "forest" -> R.style.ThemeOverlay_FireTunnel_Forest
            "amethyst" -> R.style.ThemeOverlay_FireTunnel_Amethyst
            else -> R.style.ThemeOverlay_FireTunnel_Fire
        }

        /** Apply the light/dark choice process-wide. */
        fun applyNightMode(settings: AppSettings) {
            AppCompatDelegate.setDefaultNightMode(when (settings.themeMode) {
                AppSettings.THEME_LIGHT -> AppCompatDelegate.MODE_NIGHT_NO
                AppSettings.THEME_DARK -> AppCompatDelegate.MODE_NIGHT_YES
                else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
            })
        }
    }
}
