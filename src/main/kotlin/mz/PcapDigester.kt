package mz

import io.pkts.PacketHandler
import io.pkts.packet.IPv4Packet
import io.pkts.packet.Packet
import io.pkts.packet.TCPPacket
import io.pkts.protocol.Protocol

class PcapDigester: PacketHandler {
    private val ipv4Pkts = mutableListOf<IPv4Packet>()
    private var otherPkts = 0
    private var tcpPkts = 0
    private var tlsPkts = 0
    private val tcpPeers = TCPeers()

    override fun nextPacket(packet: Packet?): Boolean {
        if (packet!!.hasProtocol(Protocol.IPv4)) {
            val ipv4pkt = packet.getPacket(Protocol.IPv4) as IPv4Packet
            val dstIP = ipv4pkt.destinationIP
            val srcIP = ipv4pkt.sourceIP
            ipv4Pkts.add(ipv4pkt)
            if (ipv4pkt.hasProtocol(Protocol.TCP)) {
                tcpPkts += 1
                val tcpPkt = ipv4pkt.getPacket(Protocol.TCP) as TCPPacket
                val srcPort = tcpPkt.sourcePort
                val dstPort = tcpPkt.destinationPort
                tcpPeers.add(srcIP, srcPort, dstIP, dstPort)
                if (tcpPkt.hasProtocol(Protocol.TLS)) {
                    tlsPkts += 1
                }
            }
        } else {
            otherPkts += 1
        }
        return true
    }

    fun getDigest(): String {
        val ips = if (ipv4Pkts.size == tcpPkts) "$tcpPkts TCP" else "$tcpPkts TCP of ${ipv4Pkts.size} IPv4"
        return "$ips packets, ($tcpPeers) $otherPkts other packets."
    }

    fun getPacketCount(): Int = ipv4Pkts.size
}

class TCPeers {
    private val all = mutableMapOf<String, SndRcv>()
    fun add(srcIP: String, srcPort: Int, dstIP: String, dstPort: Int) {
        val sd = "$srcIP:$srcPort - $dstIP:$dstPort"
        val ds = "$dstIP:$dstPort - $srcIP:$srcPort"
        val sr: SndRcv?
        when {
            all.containsKey(sd) -> {
                sr = all[sd]
                all[sd] = SndRcv(sr!!.s+1, sr.r)
            }
            all.containsKey(ds) -> {
                sr = all[ds]
                all[ds] = SndRcv(sr!!.s, sr.r+1)
            }
            else -> {
                all[sd] = SndRcv(1,0)
            }
        }
    }

    override fun toString(): String {
        val sb: StringBuilder = java.lang.StringBuilder()
        sb.append(all.size).append(" TCP peers:")
        all.forEach{ sb.append(" ${it.key} ${it.value}") }
        return  sb.toString()
    }
}

data class SndRcv(val s: Int, val r: Int) {
    override fun toString(): String {
        return "Sent: $s/Recv: $r"
    }
}
