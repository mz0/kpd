package mz

import java.io.IOException
import java.io.InputStream

class PcapStream {
    fun digest(fis: InputStream, pcapName: String) {
        var bb = ByteArray(24)

        var bytesRead = fis.read(bb, 0, 24)
        if (bytesRead > 23 && isPcapFile(bb.sliceArray(0..3))) {
            App.log.info("file ${pcapName}, read: $bytesRead Bytes.\n" +
                    "magic is OK. nanosecond timestamps: ${nanoTimestamped}; reverse byte-order: $isForeignByteOrder")
            App.log.info("Raw file header: ${bb.toHexString()}")
            println(examine(fis))
        } else {
            App.log.error("PCAP magic not found")
        }
    }
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
}

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
val ms_nbo = bytes(0xA1, 0xB2, 0xC3, 0xD4)
val ns_nbo = bytes(0xA1, 0xB2, 0x3C, 0x4D)
val ms_rbo = bytes(0xD4, 0xC3, 0xB2, 0xA1)
var ns_rbo = bytes(0x4D, 0x3C, 0xB2, 0xA1)
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