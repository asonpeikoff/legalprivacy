package org.legalprivacy.core

/**
 * IPv4 /8 blocks that IANA's registry (iana.org/assignments/ipv4-address-space) lists as US Department of Defense
 * and agencies: the noise never visits a site that resolves into one. (The desktop app also avoids Virginia; that list is
 * about 120,000 ranges, too big to carry here.)
 */
object GovNets {
    val FIRST_OCTETS = setOf(6, 11, 22, 26, 28, 29, 30, 33, 55, 214, 215)

    fun contains(ip: String): Boolean {
        val p = ip.trim().split('.')
        if (p.size != 4) return false
        val a = p[0].toIntOrNull() ?: return false
        return a in FIRST_OCTETS
    }
}
