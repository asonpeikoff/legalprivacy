package org.legalprivacy.noise

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder

/** Keeps the noise going in the background, with a notification you can always see (and stop it from). */
class NoiseService : Service() {
    companion object {
        const val ACTION_START = "org.legalprivacy.noise.START"
        const val ACTION_STOP = "org.legalprivacy.noise.STOP"
        @Volatile var engine: NoiseEngine? = null
        val running: Boolean get() = engine?.running == true

        fun start(ctx: Context) {
            val i = Intent(ctx, NoiseService::class.java).setAction(ACTION_START)
            ctx.startForegroundService(i)
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, NoiseService::class.java).setAction(ACTION_STOP))
        }
    }

    private val dot = DotClient()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            engine?.stop(); engine = null
            Prefs(this).wantedRunning = false
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        val prefs = Prefs(this)
        prefs.wantedRunning = true
        if (engine?.running != true) {
            engine = NoiseEngine(applicationContext, prefs, dot).also { it.start() }
        }
        return START_STICKY                                     // if the system stops the service, it starts it again
    }

    override fun onDestroy() {
        engine?.stop(); engine = null
        dot.close()
        super.onDestroy()
    }

    private fun notification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("noise", "Noise running", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, NoiseService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, "noise")
            .setContentTitle("legalPrivacy noise is running")
            .setContentText("Tap to open. It only uses data you allowed.")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .setOngoing(true)
            .build()
    }
}
