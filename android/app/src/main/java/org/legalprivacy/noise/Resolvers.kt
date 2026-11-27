package org.legalprivacy.noise

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** A DNS-over-TLS resolver (RFC 7858, port 853): connected by address, certificate checked against its name. */
class Resolver(val ip: String, val host: String)

val RESOLVERS = listOf(
    Resolver("9.9.9.9", "dns.quad9.net"),
    Resolver("1.1.1.1", "one.one.one.one"),
    Resolver("8.8.8.8", "dns.google"),
)

/** Sends DNS messages over TLS, trying each resolver in turn; keeps one connection per resolver open between queries. */
class DotClient(private val resolvers: List<Resolver> = RESOLVERS) {
    private class Conn(val sock: SSLSocket, val out: DataOutputStream, val inp: DataInputStream)

    private val conns = HashMap<String, Conn>()
    @Volatile var lastOkResolver: String? = null

    @Synchronized fun query(msg: ByteArray): ByteArray? {
        for (r in resolvers) {
            val answer = tryResolver(r, msg) ?: tryResolver(r, msg)       // a second try opens a fresh connection
            if (answer != null) { lastOkResolver = r.host; return answer }
        }
        return null
    }

    private fun tryResolver(r: Resolver, msg: ByteArray): ByteArray? {
        return try {
            val c = conns[r.ip] ?: open(r).also { conns[r.ip] = it }
            c.out.writeShort(msg.size); c.out.write(msg); c.out.flush()
            val n = c.inp.readUnsignedShort()
            val resp = ByteArray(n)
            c.inp.readFully(resp)
            resp
        } catch (e: Exception) {
            conns.remove(r.ip)?.let { runCatching { it.sock.close() } }
            null
        }
    }

    private fun open(r: Resolver): Conn {
        val plain = Socket()
        plain.connect(InetSocketAddress(r.ip, 853), 6000)
        plain.soTimeout = 6000
        val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(plain, r.host, 853, true) as SSLSocket
        val params: SSLParameters = ssl.sslParameters
        params.serverNames = listOf(SNIHostName(r.host))
        params.endpointIdentificationAlgorithm = "HTTPS"                    // the certificate must be for this name
        ssl.sslParameters = params
        ssl.startHandshake()
        return Conn(ssl, DataOutputStream(ssl.outputStream.buffered()), DataInputStream(ssl.inputStream.buffered()))
    }

    @Synchronized fun close() {
        conns.values.forEach { runCatching { it.sock.close() } }
        conns.clear()
    }
}
