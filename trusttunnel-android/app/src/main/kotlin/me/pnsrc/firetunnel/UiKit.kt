package me.pnsrc.firetunnel

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.widget.TextView
import androidx.annotation.AttrRes
import androidx.core.content.ContextCompat
import androidx.core.widget.TextViewCompat
import com.google.android.material.color.MaterialColors
import me.pnsrc.firetunnel.data.ConfigFields
import me.pnsrc.firetunnel.data.VpnConfig
import com.google.android.material.R as MaterialR

/** Small view helpers shared by the redesigned screens. */
object UiKit {

    /** Pills are coloured by meaning, so that the colour does the reading. */
    enum class Tone { OK, WARN, ERROR, NEUTRAL }

    /** Latency above this is shown as a warning. */
    private const val SLOW_PING_MS = 150L

    fun themeColor(context: Context, @AttrRes attr: Int): Int =
        MaterialColors.getColor(context, attr, Color.GRAY)

    /** Return the (background, foreground) pair for a [tone]. */
    fun toneColors(context: Context, tone: Tone): Pair<Int, Int> = when (tone) {
        Tone.OK -> ContextCompat.getColor(context, R.color.status_ok_container) to
            ContextCompat.getColor(context, R.color.status_on_ok_container)
        Tone.WARN -> ContextCompat.getColor(context, R.color.status_warn_container) to
            ContextCompat.getColor(context, R.color.status_warn)
        Tone.ERROR -> themeColor(context, MaterialR.attr.colorErrorContainer) to
            themeColor(context, MaterialR.attr.colorOnErrorContainer)
        Tone.NEUTRAL -> themeColor(context, MaterialR.attr.colorSurfaceVariant) to
            themeColor(context, MaterialR.attr.colorOnSurfaceVariant)
    }

    /** Colour a `bg_pill` TextView, including its compound drawables. */
    fun stylePill(view: TextView, tone: Tone) {
        val (bg, fg) = toneColors(view.context, tone)
        view.backgroundTintList = ColorStateList.valueOf(bg)
        view.setTextColor(fg)
        TextViewCompat.setCompoundDrawableTintList(view, ColorStateList.valueOf(fg))
    }

    /** Show a ping result: "42 ms" (green), slow (amber) or unreachable (grey). */
    fun showPing(view: TextView, ms: Long?) {
        val ctx = view.context
        if (ms == null) {
            view.text = ctx.getString(R.string.ping_short_unreachable)
            stylePill(view, Tone.NEUTRAL)
        } else {
            view.text = ctx.getString(R.string.ping_short_ms, ms)
            stylePill(view, if (ms <= SLOW_PING_MS) Tone.OK else Tone.WARN)
        }
    }

    /** Describe a config's endpoint: `host:443 · HTTP/2`. */
    fun endpointSummary(config: VpnConfig): String {
        val address = ConfigFields.firstEndpointAddress(config.rawToml)
            ?.let { if (':' in it.host) "[${it.host}]:${it.port}" else "${it.host}:${it.port}" }
        val protocol = ConfigFields.upstreamProtocol(config.rawToml)
        return listOfNotNull(address, protocol).joinToString(" · ")
    }
}
