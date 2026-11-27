package org.legalprivacy.core

/** IPv4/UDP framing for the local DNS VPN: read a DNS query out of a TUN packet, wrap the answer back into one. */
object Packets {
    class UdpQuery(val srcIp: ByteArray, val dstIp: ByteArray, val srcPort: Int, val dstPort: Int, val payload: ByteArray)

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)

    /** The UDP datagram inside an IPv4 packet of [len] bytes, or null if it is anything else (TCP, IPv6, fragments). */
    fun parseUdp(pkt: ByteArray, len: Int): UdpQuery? {
        if (len < 28 || (pkt[0].toInt() shr 4) != 4) return null
        val ihl = (pkt[0].toInt() and 0x0f) * 4
        if (ihl < 20 || len < ihl + 8 || pkt[9].toInt() != 17) return null
        if (u16(pkt, 6) and 0x3fff != 0) return null                      // fragment
        val total = minOf(u16(pkt, 2), len)
        val udpLen = u16(pkt, ihl + 4)
        if (udpLen < 8 || ihl + udpLen > total) return null
        return UdpQuery(pkt.copyOfRange(12, 16), pkt.copyOfRange(16, 20), u16(pkt, ihl), u16(pkt, ihl + 2),
            pkt.copyOfRange(ihl + 8, ihl + udpLen))
    }

    /** An IPv4/UDP packet carrying [payload] back to the sender of [q] (addresses and ports swapped). */
    fun reply(q: UdpQuery, payload: ByteArray): ByteArray {
        val total = 20 + 8 + payload.size
        val p = ByteArray(total)
        p[0] = 0x45; p[2] = (total shr 8).toByte(); p[3] = total.toByte()
        p[8] = 64; p[9] = 17
        q.dstIp.copyInto(p, 12); q.srcIp.copyInto(p, 16)
        val sum = checksum(p, 0, 20)
        p[10] = (sum shr 8).toByte(); p[11] = sum.toByte()
        p[20] = (q.dstPort shr 8).toByte(); p[21] = q.dstPort.toByte()
        p[22] = (q.srcPort shr 8).toByte(); p[23] = q.srcPort.toByte()
        val ul = 8 + payload.size
        p[24] = (ul shr 8).toByte(); p[25] = ul.toByte()                    // UDP checksum 0 = none (allowed over IPv4)
        payload.copyInto(p, 28)
        return p
    }

    fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var s = 0L
        var i = off
        while (i + 1 < off + len) { s += u16(b, i); i += 2 }
        if (len % 2 == 1) s += (b[off + len - 1].toInt() and 0xff) shl 8
        while (s shr 16 != 0L) s = (s and 0xffff) + (s shr 16)
        return (s.inv() and 0xffff).toInt()
    }
}
