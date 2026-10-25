package me.pnsrc.firetunnel

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.transition.TransitionManager
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.ViewCompat
import com.google.android.material.appbar.MaterialToolbar
import me.pnsrc.firetunnel.data.UpdateManager

/** Settings → Help: every feature explained, as expandable topics. */
class HelpActivity : ThemedActivity() {

    private data class Topic(val icon: Int, val title: Int, val body: Int)

    private val topics = listOf(
        Topic(R.drawable.ic_ft_shield_check, R.string.help_start_title, R.string.help_start_body),
        Topic(R.drawable.ic_ft_power, R.string.help_connect_title, R.string.help_connect_body),
        Topic(R.drawable.ic_ft_server, R.string.help_servers_title, R.string.help_servers_body),
        Topic(R.drawable.ic_ft_file, R.string.help_configs_title, R.string.help_configs_body),
        Topic(R.drawable.ic_ft_cloud, R.string.help_enroll_title, R.string.help_enroll_body),
        Topic(R.drawable.ic_ft_wand, R.string.help_constructor_title, R.string.help_constructor_body),
        Topic(R.drawable.ic_ft_apps, R.string.help_apps_title, R.string.help_apps_body),
        Topic(R.drawable.ic_ft_globe, R.string.help_sites_title, R.string.help_sites_body),
        Topic(R.drawable.ic_ft_lock, R.string.help_always_on_title, R.string.help_always_on_body),
        Topic(R.drawable.ic_ft_live, R.string.help_live_title, R.string.help_live_body),
        Topic(R.drawable.ic_ft_palette, R.string.help_appearance_title, R.string.help_appearance_body),
        Topic(R.drawable.ic_ft_down, R.string.help_updates_title, R.string.help_updates_body),
        Topic(R.drawable.ic_ft_logs, R.string.help_logs_title, R.string.help_logs_body),
        Topic(R.drawable.ic_ft_info, R.string.help_privacy_title, R.string.help_privacy_body),
        Topic(R.drawable.ic_ft_terminal, R.string.help_trouble_title, R.string.help_trouble_body),
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_help)
        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        val container = findViewById<LinearLayout>(R.id.helpTopics)
        for (topic in topics) container.addView(topicView(container, topic))

        SettingRow(findViewById(R.id.helpOpenLogs))
            .bind(R.drawable.ic_ft_logs, getString(R.string.logs_title), getString(R.string.help_open_logs_sub))
            .asLink { startActivity(Intent(this, LogsActivity::class.java)) }
        SettingRow(findViewById(R.id.helpReportIssue))
            .bind(R.drawable.ic_ft_code, getString(R.string.help_report), getString(R.string.help_report_sub))
            .asLink {
                runCatching {
                    startActivity(Intent(Intent.ACTION_VIEW,
                        Uri.parse("https://github.com/${UpdateManager.REPO}/issues")))
                }
            }
    }

    private fun topicView(parent: ViewGroup, topic: Topic): View {
        val card = layoutInflater.inflate(R.layout.item_help_topic, parent, false)
        val header = card.findViewById<View>(R.id.helpHeader)
        val body = card.findViewById<TextView>(R.id.helpBody)
        val chevron = card.findViewById<ImageView>(R.id.helpChevron)
        card.findViewById<ImageView>(R.id.helpIcon).setImageResource(topic.icon)
        card.findViewById<TextView>(R.id.helpTitle).setText(topic.title)
        body.setText(topic.body)
        header.contentDescription = getString(topic.title)
        ViewCompat.setStateDescription(header, getString(R.string.help_collapsed))
        header.setOnClickListener {
            val expand = body.visibility != View.VISIBLE
            TransitionManager.beginDelayedTransition(parent)
            body.visibility = if (expand) View.VISIBLE else View.GONE
            chevron.animate().rotation(if (expand) 270f else 90f).setDuration(200).start()
            ViewCompat.setStateDescription(header,
                getString(if (expand) R.string.help_expanded else R.string.help_collapsed))
        }
        return card
    }
}
