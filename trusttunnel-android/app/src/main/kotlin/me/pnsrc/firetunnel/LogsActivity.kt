package me.pnsrc.firetunnel

import android.os.Bundle
import com.google.android.material.appbar.MaterialToolbar

/** Hosts [LogsFragment]; opened from Settings → Diagnostics. */
class LogsActivity : ThemedActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_logs)
        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }
        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(R.id.logsContainer, LogsFragment())
                .commit()
        }
    }
}
