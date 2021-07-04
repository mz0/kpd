package mz

import io.pkts.Pcap
import org.apache.logging.log4j.LogManager
import java.io.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import kotlin.system.exitProcess
import org.tukaani.xz.XZInputStream
import java.sql.DriverManager
import java.sql.SQLException
import java.util.zip.GZIPInputStream

operator fun Regex.contains(text: CharSequence): Boolean = this.matches(text)

class App {
    companion object {
        val log = LogManager.getLogger("Z")
    }
    val version = "0.1"
    private val configFile = "application.properties"
    private val configProps: Properties by lazy {
        val tmpProp = Properties()
        log.info("Current dir (user.dir): ${System.getProperty("user.dir")}")
        try {
            if (File(configFile).isFile) { // from current dir
                log.info("Reading $configFile")
                tmpProp.load(FileInputStream(configFile))
            } else {
                log.warn("Reading built-in $configFile")
                tmpProp.load(App::class.java.classLoader.getResource(configFile).openStream())
            }
        } catch (e: IOException) {
            log.error("Error loading ${configFile}: ${e.message}")
            exitProcess(1)
        } catch (e: IllegalArgumentException) {
            log.error("Error reading ${configFile}: ${e.message}")
            exitProcess(1)
        }
        tmpProp
    }
    private lateinit var dirs: Set<Path>

    fun init(): App {
        log.info("Configuration:")
        configProps.forEach {
            (k, v) -> log.info("$k : $v")
            val dirList: MutableSet<Path> = mutableSetOf()
            if (k.toString().startsWith("dir.")) {
                val dir: Path = File(v.toString()).toPath()
                if (Files.isDirectory(dir)) {
                    if (!dirList.add(dir)) log.warn("$v is already listed!")
                } else {
                    log.error("'$v' is not a directory!")
                }
            }
            dirs = dirList
        }
        if (dirs.isEmpty()) log.error("No dirs to process!")
        return this
    }

    fun processDirs() {
        dirs.forEach(this@App::processDir)
    }
    private val pcapBare = ".*\\.pcap$".toRegex()
    private val pcapXz = ".*\\.pcap\\.xz$".toRegex()
    private val pcapGz = ".*\\.pcap\\.gz$".toRegex()
    private val pd = PcapDigester()
    private fun processDir(dir: Path) {
        println("Processing $dir start")
        dir.toFile().listFiles{f -> f.isFile}.forEach fit@{
            if (it.length() < 24) {
                log.warn("File ${it.name} has less than 24 bytes.")
                return@fit
            }
            try {
                when (it.name) {
                    in pcapBare ->
                        Pcap.openStream(FileInputStream(it)).loop(pd)
                    in pcapXz ->
                        Pcap.openStream(XZInputStream(BufferedInputStream(FileInputStream(it)))).loop(pd)
                    in pcapGz ->
                        Pcap.openStream(GZIPInputStream(BufferedInputStream(FileInputStream(it)))).loop(pd)
                    else ->
                        log.error("File ${it.name} has unknown 'extension'. Can process only .pcap/.pcap.gz/.pcap.xz")
                }
            } catch (e: IndexOutOfBoundsException) {
                // io.pkts.buffer.BoundedInputStreamBuffer.readBytes() when reading a truncated PCAP may
                // result in e.g. 'Not enough bytes left in the stream. Wanted 60 but only read 16'
                log.warn("Reading ${it.name}. Error: ${e.message}")
            }
            print("File ${it.name} - ${pd.getPacketCount()} packets; ")
        }
        println("\nFinished $dir")
    }
}

fun main(args: Array<String>) {
    val app = App().init()
    app.processDirs()

    if (false) sqlServerCheck()
}

fun sqlServerCheck() {
    val connUrl = "jdbc:sqlserver://localhost:14331;databaseName=shsha;user=shsha;password=Cook1770"
    val insertStmt = """INSERT INTO pkt ("id", captDay, pktBytes) VALUES (?, 18697, ?)"""
    try {
        DriverManager.getConnection(connUrl).use {
            it.prepareStatement(insertStmt).use { s ->
                val c2048 = "0123456789ABCDEF".repeat(16*4*2) // 16*16*4*2 = 2048
                var longtext = c2048
                for (i in 1..6) {
                    s.setInt(1, 3 + i)
                    s.setString(2, longtext)
                    s.execute()
                    longtext += longtext // pkt2 4096, pkt3 8192, pkt4 16384, pkt5 32768, pkt6 65536
                }
            }
        }
    } catch (e: SQLException) {
        println(e)
    }
}
