package org.legalprivacy.noise

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import org.legalprivacy.core.Dns
import org.legalprivacy.core.GovNets
import org.legalprivacy.core.Pacing
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.Random

/** What the phone's own (real) DNS lookups are doing, so the noise can keep step with real use. Updated by DnsVpnService. */
object RealActivity {
    @Volatile var lastLookupMs = 0L
    @Volatile var lookups = 0L
}

/**
 * The noise: now and then a burst of DNS lookups, a page visit, or a search, at random gaps around the chosen average.
 * Everything is thrown away; nothing is stored. It never stops by itself because of failures (it just waits and tries again).
 */
class NoiseEngine(private val ctx: Context, private val prefs: Prefs, private val dot: DotClient) {
    private val rng = Random()
    private val domains: List<String> = ctx.assets.open("domains.txt").bufferedReader().readLines().filter { it.isNotBlank() }
    private val queries: List<String> = ctx.assets.open("queries.txt").bufferedReader().readLines().filter { it.isNotBlank() }
    @Volatile private var thread: Thread? = null
    @Volatile var running = false
    @Volatile var lastNote = ""

    private val uas = listOf(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
    )

    @Synchronized fun start() {
        if (running) return
        running = true
        thread = Thread({ loop() }, "noise").also { it.isDaemon = true; it.start() }
        Log.add("Noise started (${prefs.level}).")
    }

    @Synchronized fun stop() {
        running = false
        thread?.interrupt()
        thread = null
        Log.add("Noise stopped.")
    }

    private fun loop() {
        while (running) {
            try {
                val perHour = (Pacing.LEVELS[prefs.level] ?: 120.0) * activityFactor()
                val gap = Pacing.gapSeconds(perHour, rng)
                var waited = 0.0
                while (running && waited < gap) { Thread.sleep(1000); waited += 1.0 }
                if (!running) break
                val why = holdReason()
                if (why != null) { lastNote = why; continue }
                lastNote = ""
                act()
            } catch (e: InterruptedException) {
                if (!running) break
            } catch (e: Exception) {
                Log.add("A step failed (${e.javaClass.simpleName}); carrying on.")
            }
        }
    }

    /** Busier while you are really using the phone, quieter when it has been idle a while. */
    private fun activityFactor(): Double {
        val last = RealActivity.lastLookupMs
        if (last == 0L) return 1.0
        val idle = (System.currentTimeMillis() - last) / 1000
        return if (idle < 60) 1.5 else if (idle > 1800) 0.5 else 1.0
    }

    private fun holdReason(): String? {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return "waiting: no network"
        val wifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        if (prefs.wifiOnly && !wifi) return "waiting: not on Wi-Fi"
        val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val charging = bm.isCharging
        if (prefs.chargingOnly && !charging) return "waiting: not charging"
        val level = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        if (!charging && level in 1..14) return "waiting: battery low"
        if (overBudget()) return "waiting: today's data limit reached"
        return null
    }

    private fun today(): String = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date())

    private fun overBudget(): Boolean {
        if (today() != prefs.usedDay) { prefs.usedDay = today(); prefs.usedBytes = 0 }
        return prefs.dailyMb > 0 && prefs.usedBytes >= prefs.dailyMb * 1_000_000L
    }

    private fun spent(n: Long) { prefs.usedBytes = prefs.usedBytes + n }

    private fun act() {
        val r = rng.nextDouble()
        when {
            r < 0.55 -> dnsBurst()
            r < 0.85 -> visit()
            else -> search()
        }
    }

    private fun pickDomain(): String = domains[rng.nextInt(domains.size)]

    /** Ask the secure resolver for a few names the way a browser does: A, AAAA, and the HTTPS record. */
    private fun dnsBurst() {
        val n = 2 + rng.nextInt(5)
        var ok = 0
        repeat(n) {
            val d = pickDomain()
            for (t in intArrayOf(Dns.A, Dns.AAAA, Dns.HTTPS)) {
                if (t != Dns.A && rng.nextInt(3) == 0) continue
                if (dot.query(Dns.query(d, t)) != null) ok++
                spent(160)
            }
        }
        Log.add("DNS: $n names, $ok answers")
    }

    /** The site's address, looked up securely; null for a banned (government) range, empty on failure. */
    private fun allowed(host: String): Boolean {
        val r = dot.query(Dns.query(host, Dns.A)) ?: return true          // not resolvable now: the visit will fail by itself
        val ip = Dns.firstA(r) ?: return true
        return !GovNets.contains(ip)
    }

    private fun fetch(url: String, limit: Int): Int {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = 8000; c.readTimeout = 10000
        c.setRequestProperty("User-Agent", uas[rng.nextInt(uas.size)])
        c.setRequestProperty("Accept-Language", "en-US,en;q=0.9")
        return try {
            val code = c.responseCode
            var total = 0
            if (code in 200..299) {
                c.inputStream.use { s ->
                    val buf = ByteArray(8192)
                    while (total < limit) { val n = s.read(buf); if (n < 0) break; total += n }
                }
            }
            spent(total.toLong() + 500)
            code
        } finally { c.disconnect() }
    }

    private fun visit() {
        var host = pickDomain()
        var tries = 0
        while (!allowed(host) && tries < 5) { host = pickDomain(); tries++ }
        val code = runCatching { fetch("https://$host/", 300_000) }.getOrElse { -1 }
        Log.add("Visit: $host ${if (code > 0) "($code)" else "(failed)"}")
    }

    private fun search() {
        val q = queries[rng.nextInt(queries.size)]
        val enc = URLEncoder.encode(q, "UTF-8")
        val duck = rng.nextInt(100) < 85                                       // DuckDuckGo mostly, a little Google
        val url = if (duck) "https://html.duckduckgo.com/html/?q=$enc" else "https://www.google.com/search?q=$enc"
        val code = runCatching { fetch(url, 150_000) }.getOrElse { -1 }
        Log.add("Search (${if (duck) "DuckDuckGo" else "Google"}): $q ${if (code > 0) "($code)" else "(failed)"}")
    }
}
