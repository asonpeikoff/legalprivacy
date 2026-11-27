package org.legalprivacy.noise

import android.content.Context
import android.content.SharedPreferences

/** The few settings, kept on the phone only. Defaults are the careful ones: Wi-Fi only, medium rate. */
class Prefs(ctx: Context) {
    private val p: SharedPreferences = ctx.getSharedPreferences("noise", Context.MODE_PRIVATE)

    var level: String
        get() = p.getString("level", "medium") ?: "medium"
        set(v) = p.edit().putString("level", v).apply()
    var wifiOnly: Boolean
        get() = p.getBoolean("wifiOnly", true)
        set(v) = p.edit().putBoolean("wifiOnly", v).apply()
    var chargingOnly: Boolean
        get() = p.getBoolean("chargingOnly", false)
        set(v) = p.edit().putBoolean("chargingOnly", v).apply()
    var dailyMb: Int                         // 0 = no cap
        get() = p.getInt("dailyMb", 50)
        set(v) = p.edit().putInt("dailyMb", v).apply()
    var dnsVpn: Boolean
        get() = p.getBoolean("dnsVpn", false)
        set(v) = p.edit().putBoolean("dnsVpn", v).apply()
    var wantedRunning: Boolean
        get() = p.getBoolean("wantedRunning", false)
        set(v) = p.edit().putBoolean("wantedRunning", v).apply()
    var usedDay: String
        get() = p.getString("usedDay", "") ?: ""
        set(v) = p.edit().putString("usedDay", v).apply()
    var usedBytes: Long
        get() = p.getLong("usedBytes", 0L)
        set(v) = p.edit().putLong("usedBytes", v).apply()
}
