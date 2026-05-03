package com.adguard.trusttunnel

enum class VpnState(val code: Int) {
    DISCONNECTED(0),
    CONNECTING(1),
    CONNECTED(2),
    WAITING_RECOVERY(3),
    RECOVERING(4),
    WAITING_FOR_NETWORK(5);

    companion object {
        private val map = entries.associateBy { it.code }
        fun getByCode(code: Int): VpnState =
            map[code] ?: throw IllegalArgumentException("Unknown VpnState code $code")
    }
}
