package me.pnsrc.firetunnel

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.MenuItem
import androidx.core.app.ActivityCompat
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.bottomnavigation.BottomNavigationView
import me.pnsrc.firetunnel.data.EnrollmentManager
import me.pnsrc.firetunnel.data.EnrollmentProtocol

class MainActivity : ThemedActivity() {

    private lateinit var bottomNav: BottomNavigationView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)

        bottomNav = findViewById(R.id.bottomNav)

        if (savedInstanceState == null) {
            showFragment(R.id.nav_vpn)
        }

        bottomNav.setOnItemSelectedListener { item ->
            showFragment(item.itemId)
            true
        }

        requestNotificationPermission()

        if (savedInstanceState == null) {
            handleDeeplink(intent)
            UpdateUi.checkIfDue(this)
        }
    }

    override fun onStart() {
        super.onStart()
        // On launch and on every return to the app (e.g. after sleep); the manager
        // throttles each link to one request per minute.
        syncEnrollments()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeeplink(intent)
    }

    // ── Device enrollment ──────────────────────────────────────────────────────

    /** Handle `firetunnel://enroll?url=…` opened from a browser or messenger. */
    private fun handleDeeplink(intent: Intent?) {
        val data = intent?.data ?: return
        if (intent.action != Intent.ACTION_VIEW
            || !data.scheme.equals(EnrollmentProtocol.DEEPLINK_SCHEME, ignoreCase = true)
        ) return
        // Consume the link so that it is not handled again on recreation.
        intent.data = null
        EnrollmentUi.confirmAndEnroll(this, data.toString()) { refreshCurrentTab() }
    }

    /** Re-check every enrollment: refresh configs, wipe revoked ones. */
    private fun syncEnrollments() {
        val appContext = applicationContext
        EnrollmentManager.runAsync({ EnrollmentManager(appContext).syncAll() }) { outcomes ->
            if (outcomes.none { it.changed }) return@runAsync
            refreshCurrentTab()
            EnrollmentUi.showSyncOutcomes(this, outcomes)
        }
    }

    private fun refreshCurrentTab() {
        if (isFinishing || isDestroyed || supportFragmentManager.isStateSaved) return
        showFragment(bottomNav.selectedItemId)
    }

    /** Set when another tab asks the Configs tab to open its "Add" sheet. */
    private var addSheetRequested = false

    /** Switch to the Configs tab, optionally opening its "Add config" sheet. */
    fun openConfigs(showAddSheet: Boolean) {
        addSheetRequested = showAddSheet
        if (bottomNav.selectedItemId == R.id.nav_configs) showFragment(R.id.nav_configs)
        else bottomNav.selectedItemId = R.id.nav_configs
    }

    /** Return true once if the "Add config" sheet was requested. */
    fun consumeAddSheetRequest(): Boolean = addSheetRequested.also { addSheetRequested = false }

    private fun showFragment(itemId: Int) {
        val fragment = when (itemId) {
            R.id.nav_vpn     -> HomeFragment()
            R.id.nav_configs -> ConfigsFragment()
            R.id.nav_rules   -> RulesFragment()
            else             -> return
        }
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, fragment)
            .commit()
    }

    override fun onCreateOptionsMenu(menu: android.view.Menu): Boolean {
        menuInflater.inflate(R.menu.toolbar_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == R.id.action_settings) {
            startActivity(Intent(this, SettingsActivity::class.java))
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),
                102
            )
        }
    }
}
