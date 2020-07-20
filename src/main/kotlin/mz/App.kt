package mz

import org.apache.logging.log4j.LogManager
import java.io.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import kotlin.system.exitProcess
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream

class App {
    companion object {
        val log = LogManager.getLogger()
    }
    val version = "0.1"
    val configFile = "application.properties"
    val configProps: Properties by lazy {
        val tmpProp = Properties()
        try {
            tmpProp.load(App::class.java.classLoader.getResource(configFile).openStream())
        } catch (e: IOException) {
            log.error("Error loading ${configFile}: ${e.message}")
            exitProcess(1)
        } catch (e: IllegalArgumentException) {
            log.error("Error reading ${configFile}: ${e.message}")
            exitProcess(1)
        }
        tmpProp
    }
    val dirs: Set<Path?> by lazy {
        val dirList: MutableSet<Path?> = mutableSetOf();
        configProps.forEach {(k, v) ->
            if (k.toString().startsWith("dir.")) {
                val dir: Path = File(v.toString()).toPath()
                if (Files.isDirectory(dir)) {
                    if (!dirList.add(dir)) log.warn("$v is already listed!")
                } else {
                    log.error("'$v' is not a directory!")
                }
            }
        }
        dirList
    }

    fun init(): App {
        configProps.forEach { (k, v) -> log.info("$k : $v") }
        if (this.dirs.isEmpty()) log.error("No dirs to process!")
        return this
    }

    fun processDirs() {
        dirs.forEach { d ->
            if (d == null) {
                log.error("no dir to process!")
            } else {
                processDir(d)
            }
        }
    }
    private val pcapBare = ".*\\.pcap$".toRegex()
    private val pcapXz = ".*\\.pcap\\.xz$".toRegex()
    private val pcapGz = ".*\\.pcap\\.gz$".toRegex()
    private fun processDir(dir: Path) {
        dir.toFile().listFiles{f -> f.isFile}.forEach fit@{ it: File ->
            if (it.length() < 24) {
                log.error("File ${it.name} has less than 24 bytes.");
                return@fit
            }

            if (it.name.matches(pcapBare)) {
                log.trace("Found ${it.name}")
                PcapStream().digest(FileInputStream(it), it.name)
            } else if (it.name.matches(pcapXz)) {
                log.info("Found XZ compressed file ${it.name}")
                PcapStream().digest(XZCompressorInputStream(BufferedInputStream(FileInputStream(it))), it.name)
            } else if (it.name.matches(pcapGz)) {
                log.info("Found GZ compressed file ${it.name}")
                PcapStream().digest(GzipCompressorInputStream(BufferedInputStream(FileInputStream(it))), it.name)
            }
        }
    }
}

fun main(args: Array<String>) {
    val app = App().init()
    app.processDirs()
}
