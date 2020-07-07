package mz

import org.apache.logging.log4j.LogManager
import java.io.IOException
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
    fun init(): App {
        configProps.forEach { (k, v) -> log.info("$k : $v") }
        return this
    }
}

fun main(args: Array<String>) {
    val app = App().init()
    //app.doFile("try10.pcap") // "/tmp/OUCH_tcpdump-20200501-000116.pcap"
}
