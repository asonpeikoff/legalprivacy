package org.legalprivacy.core

import java.util.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CoreTest {
    @Test fun queryRoundTripsItsName() {
        val q = Dns.query("www.Example.com.", Dns.A, id = 0x1234)
        assertEquals(0x1234, Dns.id(q))
        assertEquals("www.example.com", Dns.questionName(q))
        assertEquals(0, Dns.rcode(q))
    }

    @Test fun servfailKeepsIdAndQuestion() {
        val q = Dns.query("a.test", Dns.AAAA, id = 7)
        val r = Dns.servfail(q)
        assertEquals(2, Dns.rcode(r)); assertEquals(7, Dns.id(r)); assertEquals("a.test", Dns.questionName(r))
    }

    @Test fun badLabelIsRefused() {
        assertTrue(runCatching { Dns.query("a".repeat(64) + ".com", Dns.A) }.isFailure)
        assertNull(Dns.questionName(ByteArray(5)))
    }

    @Test fun firstAIsParsedFromAnAnswer() {
        val q = Dns.query("x.test", Dns.A, id = 1)
        val ans = byteArrayOf(0xc0.toByte(), 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 11, 1, 2, 3)
        val r = q.copyOf(); r[2] = 0x81.toByte(); r[3] = 0x80.toByte(); r[7] = 1
        assertEquals("11.1.2.3", Dns.firstA(r + ans))
    }

    @Test fun govBlocks() {
        assertTrue(GovNets.contains("11.2.3.4")); assertTrue(GovNets.contains("214.0.0.1"))
        assertFalse(GovNets.contains("8.8.8.8")); assertFalse(GovNets.contains("x")); assertFalse(GovNets.contains("1.2.3"))
    }

    @Test fun udpPacketRoundTrip() {
        val dns = Dns.query("example.org", Dns.A, id = 9)
        val len = 28 + dns.size
        val pkt = ByteArray(len)
        pkt[0] = 0x45; pkt[2] = (len shr 8).toByte(); pkt[3] = len.toByte(); pkt[8] = 64; pkt[9] = 17
        byteArrayOf(10, 0, 0, 1).copyInto(pkt, 12); byteArrayOf(10, 0, 0, 2).copyInto(pkt, 16)
        pkt[20] = 0x30; pkt[21] = 0x39; pkt[23] = 53
        val ul = 8 + dns.size; pkt[24] = (ul shr 8).toByte(); pkt[25] = ul.toByte()
        dns.copyInto(pkt, 28)
        val q = assertNotNull(Packets.parseUdp(pkt, len))
        assertEquals(53, q.dstPort); assertEquals(12345, q.srcPort); assertContentEquals(dns, q.payload)
        val back = Packets.reply(q, Dns.servfail(dns))
        val rq = assertNotNull(Packets.parseUdp(back, back.size))
        assertEquals(53, rq.srcPort); assertEquals(12345, rq.dstPort)
        assertContentEquals(byteArrayOf(10, 0, 0, 2), rq.srcIp); assertContentEquals(byteArrayOf(10, 0, 0, 1), rq.dstIp)
        assertEquals(0, Packets.checksum(back, 0, 20))                 // a valid IPv4 header sums to zero
    }

    @Test fun nonUdpAndShortPacketsAreIgnored() {
        assertNull(Packets.parseUdp(ByteArray(10), 10))
        val tcp = ByteArray(40); tcp[0] = 0x45; tcp[9] = 6
        assertNull(Packets.parseUdp(tcp, 40))
    }

    @Test fun pacingAveragesNearTheRate() {
        val rng = Random(3)
        val gaps = (1..4000).map { Pacing.gapSeconds(120.0, rng) }
        val mean = gaps.average()
        assertTrue(mean in 25.0..35.0, "mean $mean")                    // 3600/120 = 30 s
        assertTrue(gaps.max() - gaps.min() > 20)                        // random, not steady
    }
}
