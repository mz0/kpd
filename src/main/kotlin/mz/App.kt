package mz

import mz.App.Companion.log
import org.apache.logging.log4j.LogManager
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import kotlin.system.exitProcess

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
    private fun processDir(dir: Path) {
        Files.walk(dir, 1).forEach fit@{ it ->
            val f = it.toFile();
            if (!f.isFile) return@fit
            if (it.fileName.toString().matches(".*\\.pcap$".toRegex())) {
                log.info("Found ${it.fileName}")
            }

            if (f.length() < 24) {
                log.error("File ${f.name} has less than 24 bytes.");
                return@fit
            }
            PcapFile().doFile(FileInputStream(f), f.name)
        }
    }
}

fun main(args: Array<String>) {
    val app = App().init()
    app.processDirs()
}
