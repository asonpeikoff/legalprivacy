package org.legalprivacy.core

import java.io.ByteArrayOutputStream
import java.util.Random

/** DNS wire format (RFC 1035), just enough for noise lookups and for relaying a phone's own lookups. */
object Dns {
    const val A = 1
    const val AAAA = 28
    const val HTTPS = 65

    /** A standard query for [name] with the recursion-desired bit, one question. */
    fun query(name: String, type: Int, id: Int = Random().nextInt(65536)): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(id shr 8); out.write(id and 0xff)
        out.write(0x01); out.write(0x00)             // flags: RD
        out.write(0); out.write(1)                   // QDCOUNT
        out.write(0); out.write(0); out.write(0); out.write(0); out.write(0); out.write(0)
        for (label in name.trim('.').split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            require(b.size in 1..63) { "bad label in $name" }
            out.write(b.size); out.write(b)
        }
        out.write(0)
        out.write(type shr 8); out.write(type and 0xff)
        out.write(0); out.write(1)                   // class IN
        return out.toByteArray()
    }

    fun rcode(msg: ByteArray): Int = if (msg.size < 4) -1 else msg[3].toInt() and 0x0f
    fun answers(msg: ByteArray): Int = if (msg.size < 8) 0 else ((msg[6].toInt() and 0xff) shl 8) or (msg[7].toInt() and 0xff)
    fun id(msg: ByteArray): Int = if (msg.size < 2) -1 else ((msg[0].toInt() and 0xff) shl 8) or (msg[1].toInt() and 0xff)

    /** The first question's name, lower case, or null when the message is malformed. */
    fun questionName(msg: ByteArray): String? {
        var i = 12
        val sb = StringBuilder()
        while (i < msg.size) {
            val n = msg[i].toInt() and 0xff
            if (n == 0) return sb.toString().lowercase()
            if (n and 0xc0 != 0 || i + n >= msg.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(msg, i + 1, n, Charsets.US_ASCII))
            i += n + 1
        }
        return null
    }

    /** A SERVFAIL reply to [query], used when no resolver could be reached (the phone retries or falls back itself). */
    fun servfail(query: ByteArray): ByteArray {
        val r = query.copyOf()
        if (r.size >= 4) {
            r[2] = (0x81).toByte()                   // QR + RD
            r[3] = (0x82).toByte()                   // RA + SERVFAIL
        }
        return r
    }

    /** The first A record's address in dotted form, if the response has one (answer parsing is deliberately minimal). */
    fun firstA(msg: ByteArray): String? {
        if (msg.size < 12) return null
        var i = 12
        val qd = ((msg[4].toInt() and 0xff) shl 8) or (msg[5].toInt() and 0xff)
        repeat(qd) {
            while (i < msg.size && msg[i].toInt() != 0) { if (msg[i].toInt() and 0xc0 == 0xc0) { i++; break }; i += (msg[i].toInt() and 0xff) + 1 }
            i += 1 + 4
        }
        repeat(answers(msg)) {
            while (i < msg.size && msg[i].toInt() != 0) { if (msg[i].toInt() and 0xc0 == 0xc0) { i++; break }; i += (msg[i].toInt() and 0xff) + 1 }
            i++
            if (i + 10 > msg.size) return null
            val type = ((msg[i].toInt() and 0xff) shl 8) or (msg[i + 1].toInt() and 0xff)
            val len = ((msg[i + 8].toInt() and 0xff) shl 8) or (msg[i + 9].toInt() and 0xff)
            i += 10
            if (type == A && len == 4 && i + 4 <= msg.size)
                return (0 until 4).joinToString(".") { (msg[i + it].toInt() and 0xff).toString() }
            i += len
        }
        return null
    }
}
