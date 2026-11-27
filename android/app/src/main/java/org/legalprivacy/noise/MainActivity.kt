package org.legalprivacy.noise

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.graphics.Typeface
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import org.legalprivacy.core.Pacing

/** One screen: start or stop, how much noise, when it may run, the optional DNS VPN, and what it has been doing. */
class MainActivity : Activity() {
    private lateinit var prefs: Prefs
    private lateinit var status: TextView
    private lateinit var toggle: Button
    private lateinit var vpnBox: CheckBox
    private lateinit var logView: TextView
    private val ui = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() { refresh(); ui.postDelayed(this, 1000) }
    }

    private fun dp(n: Int) = (n * resources.displayMetrics.density).toInt()

    private fun text(s: String, size: Float = 14f, bold: Boolean = false) = TextView(this).apply {
        text = s; textSize = size
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setPadding(0, dp(6), 0, dp(2))
    }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        prefs = Prefs(this)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(12), dp(16), dp(24)) }

        col.addView(text("legalPrivacy Noise", 22f, true))
        col.addView(text("Makes believable background lookups, page visits and searches from this phone, so what your network " +
            "can see of you says less. Everything it fetches is thrown away. Nothing leaves the phone except those requests."))

        status = text("", 16f, true)
        col.addView(status)
        toggle = Button(this).apply { setOnClickListener { onToggle() } }
        col.addView(toggle)

        col.addView(text("How much", 16f, true))
        val group = RadioGroup(this)
        val names = mapOf("low" to "Low (about 30 an hour)", "medium" to "Medium (about 120 an hour)", "high" to "High (about 400 an hour)")
        for ((k, label) in names) {
            group.addView(RadioButton(this).apply { text = label; id = View.generateViewId(); tag = k; isChecked = prefs.level == k })
        }
        group.setOnCheckedChangeListener { g, id -> prefs.level = g.findViewById<RadioButton>(id).tag as String }
        col.addView(group)

        col.addView(text("When it may run", 16f, true))
        col.addView(CheckBox(this).apply {
            text = "Only on Wi-Fi (recommended)"; isChecked = prefs.wifiOnly
            setOnCheckedChangeListener { _, v -> prefs.wifiOnly = v }
        })
        col.addView(CheckBox(this).apply {
            text = "Only while charging"; isChecked = prefs.chargingOnly
            setOnCheckedChangeListener { _, v -> prefs.chargingOnly = v }
        })
        val capRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        capRow.addView(TextView(this).apply { text = "Daily data limit (MB, 0 = none): " })
        capRow.addView(EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER; setText(prefs.dailyMb.toString()); minEms = 4
            setOnFocusChangeListener { _, focus -> if (!focus) prefs.dailyMb = text.toString().toIntOrNull()?.coerceIn(0, 100000) ?: 50 }
        })
        col.addView(capRow)

        col.addView(text("Encrypt this phone's own DNS (optional)", 16f, true))
        vpnBox = CheckBox(this).apply {
            text = "Local DNS VPN: send my real lookups over TLS to a secure resolver"
            setOnClickListener { onVpnToggle() }
        }
        col.addView(vpnBox)
        col.addView(text("A VPN that only carries DNS lookups; your other traffic is not touched. It does not hide which sites you " +
            "connect to. Android allows one VPN at a time, and Android's Private DNS setting, if set to a named provider, " +
            "bypasses it (use Off or Automatic).", 12f))

        col.addView(text("What it is doing", 16f, true))
        logView = TextView(this).apply { typeface = Typeface.MONOSPACE; textSize = 11f }
        col.addView(logView)
        col.addView(Button(this).apply { text = "Clear log"; setOnClickListener { Log.clear(); refresh() } })

        col.addView(text("About", 16f, true))
        col.addView(text("Search words and site names come from the same public lists as the desktop app (Tranco top sites; " +
            "MS MARCO and GooAQ queries; Google Trends, Wikipedia and BBC headlines). The noise never visits sites that resolve " +
            "into US Department of Defense address blocks. This phone app has no Tor and no relay.", 12f))

        setContentView(ScrollView(this).apply { addView(col) })
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        if (prefs.wantedRunning && !NoiseService.running) NoiseService.start(this)    // it was on when the phone last stopped it
    }

    private fun onToggle() {
        if (NoiseService.running) NoiseService.stop(this) else NoiseService.start(this)
        ui.postDelayed({ refresh() }, 400)
    }

    private fun onVpnToggle() {
        if (!vpnBox.isChecked) {
            startService(Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            return
        }
        val ask = VpnService.prepare(this)
        if (ask != null) startActivityForResult(ask, 7) else startVpn()
    }

    private fun startVpn() = startService(Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START))

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 7) {
            if (resultCode == RESULT_OK) startVpn() else vpnBox.isChecked = false
        }
    }

    private fun refresh() {
        val on = NoiseService.running
        val note = NoiseService.engine?.lastNote.orEmpty()
        status.text = if (on) (if (note.isEmpty()) "Running" else "Running, $note") else "Stopped"
        toggle.text = if (on) "Stop" else "Start"
        vpnBox.isChecked = DnsVpnService.active
        val cap = prefs.dailyMb
        val b = prefs.usedBytes
        val used = if (b < 1_000_000) "${b / 1000} KB" else String.format(java.util.Locale.US, "%.1f MB", b / 1_000_000.0)
        val vpn = if (DnsVpnService.active) "   |   DNS VPN: ${RealActivity.lookups} of your lookups carried" else ""
        val line = "Today: about $used used" + (if (cap > 0) " of $cap MB" else "") +
            "   |   level ${prefs.level} (${Pacing.LEVELS[prefs.level]?.toInt()} an hour)$vpn\n"
        logView.text = line + Log.text()
    }

    override fun onResume() { super.onResume(); ui.post(tick) }
    override fun onPause() { ui.removeCallbacks(tick); super.onPause() }
}
