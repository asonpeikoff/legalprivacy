package org.legalprivacy.noise

import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.legalprivacy.core.Dns
import org.legalprivacy.core.Packets
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.Executors

/**
 * A local, DNS-only VPN. Only one address (the DNS server this VPN hands the phone) is routed into it, so the phone's
 * other traffic is untouched and goes out as usual. Every DNS lookup the phone makes arrives here and is sent on over
 * TLS to a secure resolver instead of in clear text to the network's. Nothing is logged but a count; the names of
 * your real lookups are never recorded.
 *
 * Limits: it does not hide which sites you connect to, only the DNS part. Android lets one VPN run at a time, and its
 * "Private DNS" setting, when set to a named provider, bypasses any VPN's DNS (turn it off or to Automatic).
 */
class DnsVpnService : VpnService() {
    companion object {
        const val ACTION_START = "org.legalprivacy.noise.VPN_START"
        const val ACTION_STOP = "org.legalprivacy.noise.VPN_STOP"
        const val DNS_ADDR = "10.111.222.2"
        @Volatile var active = false
    }

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var reader: Thread? = null
    private val pool = Executors.newFixedThreadPool(6)
    private val dot = DotClient()

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { shutdown(); stopSelf(); return START_NOT_STICKY }
        if (!active) establish()
        return START_STICKY
    }

    private fun establish() {
        val fd = Builder()
            .setSession("legalPrivacy DNS")
            .addAddress("10.111.222.1", 32)
            .addDnsServer(DNS_ADDR)
            .addRoute(DNS_ADDR, 32)                      // only DNS comes here; everything else is untouched
            .setBlocking(true)
            .also { runCatching { it.addDisallowedApplication(packageName) } }   // our own lookups go out directly
            .establish()
        if (fd == null) { Log.add("DNS VPN: Android did not allow it (permission not given?)."); return }
        tun = fd
        active = true
        Prefs(this).dnsVpn = true
        Log.add("DNS VPN on: your lookups now go out over TLS.")
        reader = Thread({ readLoop(fd) }, "dns-vpn").also { it.isDaemon = true; it.start() }
    }

    private fun readLoop(fd: ParcelFileDescriptor) {
        val inp = FileInputStream(fd.fileDescriptor)
        val out = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        var served = 0L
        try {
            while (active) {
                val n = inp.read(buf)
                if (n < 0) break
                if (n == 0) continue
                val q = Packets.parseUdp(buf, n) ?: continue
                if (q.dstPort != 53) continue
                RealActivity.lastLookupMs = System.currentTimeMillis()
                RealActivity.lookups++
                pool.execute {
                    val resp = dot.query(q.payload) ?: Dns.servfail(q.payload)
                    val pkt = Packets.reply(q, resp)
                    synchronized(out) { runCatching { out.write(pkt) } }
                }
                served++
                if (served % 200 == 0L) Log.add("DNS VPN: $served lookups carried so far")
            }
        } catch (e: Exception) {
            if (active) Log.add("DNS VPN stopped: ${e.javaClass.simpleName}")
        }
    }

    private fun shutdown() {
        active = false
        Prefs(this).dnsVpn = false
        runCatching { tun?.close() }
        tun = null
        reader?.interrupt()
        dot.close()
        Log.add("DNS VPN off.")
    }

    override fun onRevoke() { shutdown(); super.onRevoke() }     // the user turned it off in Android's settings

    override fun onDestroy() {
        shutdown()
        pool.shutdownNow()
        super.onDestroy()
    }
}
