package com.trusttunnel.android.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import java.io.File

data class VpnConfig(
    val id: String,
    val name: String,
    val host: String,
    val port: Int,
    val protocol: String,
    val certPin: String,
    val proxyIp: String = "",
    val routeAll: Boolean = true
)

class ConfigManager(private val context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("configs", Context.MODE_PRIVATE)
    private val configDir = File(context.filesDir, "configs")

    init {
        configDir.mkdirs()
    }

    fun getConfigs(): List<VpnConfig> {
        val configList = mutableListOf<VpnConfig>()
        val allPrefs = prefs.all

        for ((key, value) in allPrefs) {
            if (key.startsWith("config_")) {
                val json = value as? String ?: continue
                configList.add(parseConfigJson(json))
            }
        }

        return configList
    }

    fun saveConfig(config: VpnConfig) {
        val json = configToJson(config)
        prefs.edit().putString("config_${config.id}", json).apply()
    }

    fun parseQRCode(qrContent: String): VpnConfig? {
        return try {
            val decoded = Base64.decode(qrContent, Base64.DEFAULT)
            val configContent = String(decoded)
            parseTomlConfig(configContent)
        } catch (e: Exception) {
            null
        }
    }

    private fun parseTomlConfig(content: String): VpnConfig? {
        return try {
            var name = "Unknown"
            var host = ""
            var port = 443
            var protocol = "https"
            var certPin = ""
            var proxyIp = ""

            content.lines().forEach { line ->
                when {
                    line.startsWith("name") -> name = extractValue(line)
                    line.startsWith("address") -> {
                        val addr = extractValue(line)
                        val parts = addr.split(":")
                        host = parts[0]
                        port = parts.getOrNull(1)?.toIntOrNull() ?: 443
                    }
                    line.startsWith("protocol") -> protocol = extractValue(line)
                    line.startsWith("cert_pin") -> certPin = extractValue(line)
                    line.startsWith("proxy_ip") -> proxyIp = extractValue(line)
                }
            }

            if (host.isNotEmpty()) {
                VpnConfig(
                    id = System.currentTimeMillis().toString(),
                    name = name,
                    host = host,
                    port = port,
                    protocol = protocol,
                    certPin = certPin,
                    proxyIp = proxyIp
                )
            } else null
        } catch (e: Exception) {
            null
        }
    }

    private fun extractValue(line: String): String {
        val parts = line.split("=", limit = 2)
        return if (parts.size > 1) {
            parts[1].trim().removeSurrounding("\"")
        } else ""
    }

    private fun configToJson(config: VpnConfig): String {
        return """
        {
            "id":"${config.id}",
            "name":"${config.name}",
            "host":"${config.host}",
            "port":${config.port},
            "protocol":"${config.protocol}",
            "certPin":"${config.certPin}",
            "proxyIp":"${config.proxyIp}",
            "routeAll":${config.routeAll}
        }
        """.trimIndent()
    }

    private fun parseConfigJson(json: String): VpnConfig {
        // Simple JSON parsing
        val id = json.extractJsonString("id")
        val name = json.extractJsonString("name")
        val host = json.extractJsonString("host")
        val port = json.extractJsonInt("port")
        val protocol = json.extractJsonString("protocol")
        val certPin = json.extractJsonString("certPin")
        val proxyIp = json.extractJsonString("proxyIp")
        val routeAll = json.extractJsonBoolean("routeAll")

        return VpnConfig(id, name, host, port, protocol, certPin, proxyIp, routeAll)
    }
}

private fun String.extractJsonString(key: String): String {
    val pattern = "\"$key\"\\s*:\\s*\"([^\"]*)\"".toRegex()
    return pattern.find(this)?.groupValues?.get(1) ?: ""
}

private fun String.extractJsonInt(key: String): Int {
    val pattern = "\"$key\"\\s*:\\s*(\\d+)".toRegex()
    return pattern.find(this)?.groupValues?.get(1)?.toIntOrNull() ?: 443
}

private fun String.extractJsonBoolean(key: String): Boolean {
    val pattern = "\"$key\"\\s*:\\s*(true|false)".toRegex()
    return pattern.find(this)?.groupValues?.get(1) == "true"
}
