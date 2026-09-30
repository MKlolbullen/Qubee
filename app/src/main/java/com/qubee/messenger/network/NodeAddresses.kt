package com.qubee.messenger.network

import org.json.JSONObject

/**
 * This device's libp2p node identity as reported by
 * `QubeeManager.getNodeAddresses()`. [dialAddrs] already carry the
 * `/p2p/<PeerId>` suffix, so another device can paste them straight
 * into its bootstrap list.
 */
data class NodeAddresses(
    val peerId: String,
    val listenAddrs: List<String>,
    val dialAddrs: List<String>,
) {
    companion object {
        fun fromJson(raw: String?): NodeAddresses? {
            if (raw.isNullOrBlank()) return null
            return runCatching {
                val obj = JSONObject(raw)
                fun list(key: String): List<String> {
                    val arr = obj.optJSONArray(key) ?: return emptyList()
                    return List(arr.length()) { arr.optString(it) }.filter { it.isNotBlank() }
                }
                NodeAddresses(
                    peerId = obj.optString("peerId"),
                    listenAddrs = list("listenAddrs"),
                    dialAddrs = list("dialAddrs"),
                )
            }.getOrNull()
        }
    }
}
