package com.adguard.trusttunnel

import android.os.ParcelFileDescriptor
import com.adguard.trusttunnel.log.NativeLogger
import com.adguard.trusttunnel.log.NativeLoggerLevel
import org.slf4j.LoggerFactory
import java.io.Closeable

/**
 * Kotlin wrapper around the native trusttunnel_android.so VPN core.
 *
 * JNI function names exported by trusttunnel_android.so:
 *   Java_com_adguard_trusttunnel_VpnClient_createNative
 *   Java_com_adguard_trusttunnel_VpnClient_startNative
 *   Java_com_adguard_trusttunnel_VpnClient_stopNative
 *   Java_com_adguard_trusttunnel_VpnClient_destroyNative
 *   Java_com_adguard_trusttunnel_VpnClient_notifyNetworkChangeNative
 *
 * IMPORTANT: The companion-object init block intentionally does NOT call
 * System.loadLibrary.  Doing so in <clinit> causes ExceptionInInitializerError
 * (wrapping UnsatisfiedLinkError) when the .so is absent, which crashes the
 * whole service.  Call [tryLoadLibrary] explicitly before instantiating this
 * class; check [nativeLibraryLoaded] before using it.
 */
class VpnClient(
    private val config: String,
    private val callbacks: VpnClientListener?
) : Closeable {

    companion object {
        private val LOG = LoggerFactory.getLogger("VpnClient")

        /** true after [tryLoadLibrary] succeeds */
        @Volatile
        var nativeLibraryLoaded: Boolean = false
            private set

        /**
         * Attempt to load the native library.  Safe to call multiple times.
         * @return true if the library is ready to use.
         */
        fun tryLoadLibrary(): Boolean {
            if (nativeLibraryLoaded) return true
            return try {
                System.loadLibrary("trusttunnel_android")
                nativeLibraryLoaded = true
                // Wire native log output to logback-android
                NativeLogger.setupNativeLogging()
                NativeLogger.defaultLogLevel = NativeLoggerLevel.INFO
                LOG.info("Native library loaded")
                true
            } catch (e: UnsatisfiedLinkError) {
                LOG.warn("trusttunnel_android.so not available: {}", e.message)
                false
            }
        }
    }

    private var nativePtr: Long = 0L
    private val sync = Any()

    /**
     * Start the VPN.
     *
     * Ownership of [vpnTunInterface] is transferred to the native layer via
     * [ParcelFileDescriptor.detachFd].  Do NOT close it afterwards.
     */
    fun start(vpnTunInterface: ParcelFileDescriptor?): Boolean = synchronized(sync) {
        nativePtr = createNative(config)
        if (nativePtr == 0L) {
            LOG.error("createNative returned null pointer")
            return false
        }
        return startNative(nativePtr, vpnTunInterface?.detachFd() ?: -1)
    }

    fun stop() = synchronized(sync) {
        if (nativePtr == 0L) return
        stopNative(nativePtr)
    }

    fun notifyNetworkChange(available: Boolean) = synchronized(sync) {
        if (nativePtr == 0L) return
        notifyNetworkChangeNative(nativePtr, available)
    }

    override fun close() = synchronized(sync) {
        if (nativePtr != 0L) {
            destroyNative(nativePtr)
            nativePtr = 0L
        }
    }

    // ── Callbacks invoked from native code via JNI ─────────────────────────────
    fun protectSocket(socket: Int): Boolean = callbacks?.protectSocket(socket) ?: false
    fun verifyCertificate(cert: ByteArray?, chain: List<ByteArray?>?): Boolean =
        callbacks?.verifyCertificate(cert, chain) ?: false
    fun onStateChanged(state: Int) = callbacks?.onStateChanged(state)
    fun onConnectionInfo(info: String) = callbacks?.onConnectionInfo(info)

    // ── JNI stubs (implemented in trusttunnel_android.so) ─────────────────────
    private external fun createNative(config: String): Long
    private external fun startNative(nativePtr: Long, tunFd: Int): Boolean
    private external fun stopNative(nativePtr: Long)
    private external fun notifyNetworkChangeNative(nativePtr: Long, available: Boolean)
    private external fun destroyNative(nativePtr: Long)
}
