package me.pnsrc.firetunnel.data

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Measure TCP connect latency to a VPN endpoint.
 *
 * FireTunnel itself always bypasses the tunnel, so this measures the real path to
 * the server whether or not the VPN is up. DNS resolution is excluded from the
 * timing. All methods block — call them off the main thread.
 */
object EndpointPinger {
    private const val TIMEOUT_MS = 3_000
    private const val ATTEMPTS = 2

    /** Return the best connect time in milliseconds, or `null` if unreachable. */
    fun ping(target: HostPort): Long? {
        val address = try {
            InetAddress.getByName(target.host)
        } catch (e: IOException) {
            return null
        }
        var best: Long? = null
        repeat(ATTEMPTS) {
            val started = System.nanoTime()
            try {
                Socket().use { it.connect(InetSocketAddress(address, target.port), TIMEOUT_MS) }
                val ms = (System.nanoTime() - started) / 1_000_000
                best = best?.let { b -> minOf(b, ms) } ?: ms
            } catch (e: IOException) {
                // Try again; one failed attempt does not make the endpoint unreachable.
            }
        }
        return best
    }
}
