package me.pnsrc.firetunnel

import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.core.view.ViewCompat
import com.google.android.material.materialswitch.MaterialSwitch

/** Binds an `item_setting_row.xml` row: icon, title, optional subtitle, then a switch or a chevron. */
class SettingRow(private val root: View) {

    private val icon: ImageView = root.findViewById(R.id.settingIcon)
    private val title: TextView = root.findViewById(R.id.settingTitle)
    private val subtitle: TextView = root.findViewById(R.id.settingSubtitle)
    private val switch: MaterialSwitch = root.findViewById(R.id.settingSwitch)
    private val chevron: View = root.findViewById(R.id.settingChevron)

    fun bind(iconRes: Int, titleText: CharSequence, subtitleText: CharSequence? = null): SettingRow {
        icon.setImageResource(iconRes)
        title.text = titleText
        setSubtitle(subtitleText)
        return this
    }

    fun setSubtitle(text: CharSequence?) {
        subtitle.text = text
        subtitle.visibility = if (text.isNullOrEmpty()) View.GONE else View.VISIBLE
    }

    /** Row that opens something: shows a chevron. */
    fun asLink(onClick: () -> Unit): SettingRow {
        chevron.visibility = View.VISIBLE
        root.setOnClickListener { onClick() }
        return this
    }

    /** Row with a switch; tapping anywhere on the row toggles it. */
    fun asSwitch(checked: Boolean, onChange: (Boolean) -> Unit): SettingRow {
        switch.visibility = View.VISIBLE
        switch.isChecked = checked
        describeState(checked)
        root.setOnClickListener {
            switch.isChecked = !switch.isChecked
            describeState(switch.isChecked)
            onChange(switch.isChecked)
        }
        return this
    }

    /** Plain informational row. */
    fun asInfo(): SettingRow {
        root.isClickable = false
        root.isFocusable = false
        root.background = null
        return this
    }

    fun setEnabled(enabled: Boolean) {
        root.isEnabled = enabled
        switch.isEnabled = enabled
        root.alpha = if (enabled) 1f else 0.5f
    }

    private fun describeState(checked: Boolean) {
        ViewCompat.setStateDescription(
            root, root.context.getString(if (checked) R.string.state_on else R.string.state_off)
        )
    }
}
