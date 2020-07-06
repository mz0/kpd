package mz

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.lang.IllegalStateException
import kotlin.system.exitProcess
import org.apache.logging.log4j.LogManager

class App {
    companion object {
        val log = LogManager.getLogger()
    }
    val version = "0.1"
}

@kotlin.ExperimentalUnsignedTypes
fun ByteArray.getUIntAt(idx: Int): UInt =
   if (isForeignByteOrder!!)
        ((this[idx+3].toUInt() and 0xFFu) shl 24) or
        ((this[idx+2].toUInt() and 0xFFu) shl 16) or
        ((this[idx+1].toUInt() and 0xFFu) shl 8)  or
         (this[idx  ].toUInt() and 0xFFu)
   else ((this[idx  ].toUInt() and 0xFFu) shl 24) or
        ((this[idx+1].toUInt() and 0xFFu) shl 16) or
        ((this[idx+2].toUInt() and 0xFFu) shl 8)  or
         (this[idx+3].toUInt() and 0xFFu)
@kotlin.ExperimentalUnsignedTypes
fun ByteArray.toHexString() = asUByteArray().joinToString("") { it.toString(16).padStart(2, '0') }
/*
https://wiki.wireshark.org/Development/LibpcapFileFormat
typedef struct pcap_hdr_s {
    guint32 magic_number;   //  0 4 0xa1b2c3d4 ms NBO/ 0xd4c3b2a1 ms-RBO
                                    0xa1b23c4d ns    / 0x4d3cb2a1 ns-RBO
    guint16 version_major;  //  4 2 major version number    =2
    guint16 version_minor;  //  6 2 minor version number    =4
    gint32  thiszone;       //  8 4 GMT to local correction
    guint32 sigfigs;        // 12 4 accuracy of timestamps, =0 as a rule
    guint32 snaplen;        // 16 4 max length of captured packets, in octets, typically 65535 or more
    guint32 network;        // 20 4 data link type 1=LINKTYPE_ETHERNET - DLT_EN10MB - IEEE 802.3 Ethernet
                                // (10Mb, 100Mb, 1000Mb, and up); the 10MB in the DLT_ name is historical
} pcap_hdr_t;
*/

fun byteArrayOfInts(vararg ints: Int) = ByteArray(ints.size) { pos -> ints[pos].toByte() }

val ms_nbo = byteArrayOfInts(0xA1, 0xB2, 0xC3, 0xD4)
val ms_rbo = byteArrayOfInts(0xD4, 0xC3, 0xB2, 0xA1)
val ns_nbo = byteArrayOfInts(0xA1, 0xB2, 0x3C, 0x4D)
var ns_rbo = byteArrayOfInts(0x4D, 0xC3, 0xB2, 0xA1)
var nanoTimestamped: Boolean? = null;
var isForeignByteOrder: Boolean? = null;

fun isPcapFile(magic: ByteArray): Boolean  {
    if (magic.contentEquals(ms_nbo)) {
        nanoTimestamped = false; isForeignByteOrder = false; return true
    } else if (magic.contentEquals(ms_rbo)) {
        nanoTimestamped = false; isForeignByteOrder = true; return true
    } else if (magic.contentEquals(ns_nbo)) {
        nanoTimestamped = true; isForeignByteOrder = false; return true
    } else if (magic.contentEquals(ns_rbo)) {
        nanoTimestamped = true; isForeignByteOrder = true; return true
    } else return false
}
/* typedef struct pcaprec_hdr_s {
 0  guint32 ts_sec;         // timestamp seconds
 4  guint32 ts_usec;        // timestamp microseconds
 8  guint32 incl_len;       // number of octets of packet saved in file
12  guint32 orig_len;       // actual length of packet
} pcaprec_hdr_t;*/
fun examine(s: InputStream): String {
    if (isForeignByteOrder == null ) throw IllegalStateException("examine() cannot proceed: byte-order flag is 'null'")
    val hlen = 16
    var truncated = 0;
    var pkts = 0
    var hdrs = 0
    var bhdr = ByteArray(16)
    var pBuf = ByteArray(65536)
    var hread = 0
    var pread = 0
    var maxLen = 0
    var incl: Long = 0
    try {
        while (true) {
            hread = s.read(bhdr)
            if (hread == -1)  {
                App.log.info("File have ended (-1 Bytes read)")
                return "examined $pread packets. Longest $maxLen Bytes"
            } else if (hread < hlen) {
                return "Error reading header ${hdrs}. ${hread} Bytes read, "
            }
            hdrs++
            println("Pcap_hdr${hdrs.toString().padStart(4, '.')}: ${bhdr.toHexString()}")
            App.log.info("incl_len field: ${bhdr.slice(8..11).toByteArray().toHexString()}")

            var incl = bhdr.getUIntAt(8)
            App.log.info("Try reading $incl Bytes")
            val pLen = s.read(pBuf, 0, incl.toInt())
            if (incl.toInt() == pLen) {
                pread++
                maxLen = if (pLen > maxLen) pLen else maxLen
            } else {
                return "error reading packet ${hdrs}. $pLen Bytes read of ${incl}"
            }
        }
    } catch (e: IOException) {
        return "examined OK $pread packets. Error: ${e.message}"
    }
    return "unexpected return. examined $pread packets. Longest $maxLen Bytes"
}

fun main(args: Array<String>) {
    val pcapName = "/tmp/try10.pcap" // "/tmp/OUCH_tcpdump-20200501-000116.pcap"

    var filePos = 0
    val f = File(pcapName)
    val fis = File(pcapName).inputStream()
    val flen = f.length()
    var bb = ByteArray(24)

    if (flen < 24) {
        println("File has less than 24 bytes. Exiting"); exitProcess(1)
    }
    var bytesRead = fis.read(bb,0,24)
    if (bytesRead > 23 && isPcapFile(bb.sliceArray(0..3))) {
        println("file ${pcapName} is a file: ${f.isFile}, has $flen bytes, read: $bytesRead Bytes.\n" +
                "magic is OK. nanosecond timestamps: ${nanoTimestamped}; reverse byte-order: $isForeignByteOrder")
        App.log.info("Raw file header: ${bb.toHexString()}")
        println(examine(fis))
    } else {
        println("PCAP magic not found")
    }
}
