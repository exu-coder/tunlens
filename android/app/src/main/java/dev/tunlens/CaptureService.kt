package dev.tunlens

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Thin shell around the Rust bridge: build the tun, hand the fd to native code,
 * and get out of the way.
 *
 * Scope is enforced here, by the framework: only the packages the user picked
 * are routed into the VPN (`addAllowedApplication`), and tunlens never captures
 * itself, so its own upstream connections cannot loop back into the tun.
 */
class CaptureService : VpnService() {

    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> start(intent.getStringArrayExtra(EXTRA_PACKAGES).orEmpty().toList())
            ACTION_STOP -> stop()
            else -> Log.w(TAG, "ignoring intent with no action")
        }
        return START_STICKY
    }

    private fun start(packages: List<String>) {
        if (tun != null) {
            return
        }
        if (packages.isEmpty()) {
            // Refusing here is the safety property: an empty allow-list would
            // mean "capture everything", which this tool never does silently.
            Log.w(TAG, "refusing to start with no selected apps")
            stopSelf()
            return
        }

        val builder = VpnService.Builder()
            .setSession("tunlens")
            .setMtu(MTU)
            .addAddress(TUN_ADDRESS, TUN_PREFIX)
            .addDnsServer(DNS_ADDRESS)
            .addRoute("0.0.0.0", 0)
            .setBlocking(false)

        // Always exclude ourselves, whatever the selection says.
        runCatching { builder.addDisallowedApplication(packageName) }
            .onFailure { Log.e(TAG, "cannot exclude self from the VPN", it) }

        val accepted = packages.filter { pkg ->
            runCatching { builder.addAllowedApplication(pkg) }
                .onFailure { Log.w(TAG, "cannot capture $pkg", it) }
                .isSuccess
        }
        if (accepted.isEmpty()) {
            Log.w(TAG, "no selected package could be captured")
            stopSelf()
            return
        }

        val descriptor = try {
            builder.establish()
        } catch (err: Exception) {
            Log.e(TAG, "establish() failed", err)
            null
        }
        if (descriptor == null) {
            // Typically the user revoked consent, or another VPN is active.
            Log.w(TAG, "VPN consent not granted")
            stopSelf()
            return
        }

        tun = descriptor
        startForegroundNotification(accepted.size)
        if (!NativeBridge.startTun(descriptor.fd)) {
            Log.e(TAG, "native bridge refused the tun fd")
            stop()
            return
        }
        Log.i(TAG, "capturing ${accepted.size} app(s) via fd ${descriptor.fd}")
    }

    private fun stop() {
        NativeBridge.stopTun()
        tun?.let {
            runCatching { it.close() }
        }
        tun = null
        stopForegroundCompat()
        stopSelf()
    }

    override fun onRevoke() {
        // The user withdrew consent or switched VPNs: clean up immediately.
        Log.i(TAG, "VPN permission revoked")
        stop()
        super.onRevoke()
    }

    override fun onDestroy() {
        NativeBridge.stopTun()
        tun?.let { runCatching { it.close() } }
        tun = null
        super.onDestroy()
    }

    private fun startForegroundNotification(appCount: Int) {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.capture_channel),
                NotificationManager.IMPORTANCE_LOW,
            )
            manager.createNotificationChannel(channel)
        }

        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText("Observing $appCount selected app(s)")
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setOngoing(true)
            .setContentIntent(open)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    companion object {
        private const val TAG = "tunlens"
        private const val CHANNEL_ID = "capture"
        private const val NOTIFICATION_ID = 1

        const val ACTION_START = "dev.tunlens.action.START"
        const val ACTION_STOP = "dev.tunlens.action.STOP"
        const val EXTRA_PACKAGES = "dev.tunlens.extra.PACKAGES"

        /** Kept in step with `TunConfig::default()` in rust/src/tun.rs. */
        private const val TUN_ADDRESS = "10.233.0.1"
        private const val TUN_PREFIX = 24
        private const val DNS_ADDRESS = "10.233.0.2"
        private const val MTU = 1500
    }
}
