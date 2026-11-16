package dev.tunlens

import android.app.Activity
import android.app.AlertDialog
import android.net.VpnService
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Minimal control panel: pick the apps to observe, start/stop, watch the event
 * log. No layout XML on purpose — the UI is small enough to read inline, and it
 * keeps the scaffold free of resource wiring.
 */
class MainActivity : Activity() {

    private lateinit var status: TextView
    private lateinit var startButton: Button
    private lateinit var logView: TextView
    private val logLines = ArrayDeque<String>()
    private val clock = SimpleDateFormat("HH:mm:ss", Locale.US)

    private val prefs by lazy { getSharedPreferences("tunlens", MODE_PRIVATE) }

    private val onEvent: (CaptureEvent) -> Unit = { event ->
        val line = "${clock.format(Date(event.tsMs))}  ${event.line()}"
        logLines.addLast(line)
        while (logLines.size > MAX_LOG_LINES) logLines.removeFirst()
        logView.text = logLines.joinToString("\n")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildUi())
        CaptureBus.register(onEvent)
        refreshStatus()
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    override fun onDestroy() {
        CaptureBus.unregister(onEvent)
        super.onDestroy()
    }

    private fun buildUi(): ViewGroup {
        val density = resources.displayMetrics.density
        fun dp(value: Int) = (value * density).toInt()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(12))
        }

        val title = TextView(this).apply {
            text = "tunlens ${NativeBridge.version()}"
            textSize = 20f
            setPadding(0, 0, 0, dp(6))
        }

        val blurb = TextView(this).apply {
            text = "Read-only view of traffic from apps you choose. " +
                "Nothing is modified, blocked or re-sent."
            textSize = 13f
            setPadding(0, 0, 0, dp(14))
        }

        status = TextView(this).apply {
            textSize = 14f
            setPadding(0, 0, 0, dp(12))
        }

        val choose = Button(this).apply {
            text = "Choose apps"
            setOnClickListener { pickApps() }
        }
        startButton = Button(this).apply {
            text = "Start capture"
            setOnClickListener { toggleCapture() }
        }
        val overlay = Button(this).apply {
            text = "Overlay"
            setOnClickListener { toggleOverlay() }
        }

        val buttons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(choose, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(startButton, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(overlay, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }

        logView = TextView(this).apply {
            text = "No events yet."
            textSize = 11f
            typeface = android.graphics.Typeface.MONOSPACE
            setPadding(dp(8), dp(8), dp(8), dp(8))
        }

        val scroller = ScrollView(this).apply {
            addView(logView)
            setPadding(0, dp(12), 0, 0)
        }

        root.addView(title)
        root.addView(blurb)
        root.addView(status)
        root.addView(buttons)
        root.addView(scroller, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        return root
    }

    private fun selectedPackages(): List<String> =
        prefs.getStringSet(KEY_PACKAGES, emptySet()).orEmpty().sorted()

    private fun refreshStatus() {
        val count = selectedPackages().size
        val running = NativeBridge.isRunning()
        status.text = when {
            running -> "Capturing $count app(s) • ${NativeBridge.connectionCount()} connection(s) seen"
            count == 0 -> "No apps selected yet."
            else -> "$count app(s) selected. Not capturing."
        }
        startButton.text = if (running) "Stop capture" else "Start capture"
    }

    private fun launchableApps(): List<Pair<String, String>> {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return packageManager.queryIntentActivities(intent, 0)
            .map { it.activityInfo.packageName to it.loadLabel(packageManager).toString() }
            .distinctBy { it.first }
            .sortedBy { it.second.lowercase(Locale.US) }
    }

    private fun pickApps() {
        val apps = launchableApps()
        if (apps.isEmpty()) {
            toast("No launchable apps found")
            return
        }
        val labels = apps.map { "${it.second}\n${it.first}" }.toTypedArray()
        val chosen = selectedPackages().toMutableSet()
        val checked = apps.map { it.first in chosen }.toBooleanArray()

        AlertDialog.Builder(this)
            .setTitle("Apps to observe")
            .setMultiChoiceItems(labels, checked) { _, which, isChecked ->
                if (isChecked) chosen.add(apps[which].first) else chosen.remove(apps[which].first)
            }
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save") { _, _ ->
                prefs.edit().putStringSet(KEY_PACKAGES, chosen).apply()
                refreshStatus()
            }
            .show()
    }

    private fun toggleCapture() {
        if (NativeBridge.isRunning()) {
            startService(
                Intent(this, CaptureService::class.java).setAction(CaptureService.ACTION_STOP)
            )
            refreshStatus()
            return
        }

        val packages = selectedPackages()
        if (packages.isEmpty()) {
            toast("Choose at least one app first")
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATIONS)
        }

        // VpnService.prepare() is the consent prompt; null means already granted.
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQ_VPN)
        } else {
            beginCapture(packages)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                beginCapture(selectedPackages())
            } else {
                toast("VPN consent declined")
            }
        }
    }

    private fun beginCapture(packages: List<String>) {
        val intent = Intent(this, CaptureService::class.java)
            .setAction(CaptureService.ACTION_START)
            .putExtra(CaptureService.EXTRA_PACKAGES, packages.toTypedArray())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        postDelayedRefresh()
    }

    private fun toggleOverlay() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            startActivity(
                Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:$packageName"),
                )
            )
            return
        }
        startService(Intent(this, OverlayService::class.java))
        toast("Overlay started; drag it anywhere")
    }

    private fun postDelayedRefresh() {
        status.postDelayed({ refreshStatus() }, 400)
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    companion object {
        private const val REQ_VPN = 1001
        private const val REQ_NOTIFICATIONS = 1002
        private const val KEY_PACKAGES = "packages"
        private const val MAX_LOG_LINES = 400
    }
}
