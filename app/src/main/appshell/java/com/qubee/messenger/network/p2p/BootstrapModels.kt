package com.qubee.messenger.network.p2p

import org.json.JSONArray
import org.json.JSONObject

enum class BootstrapTransportPreference {
    WifiDirectBle,
    WifiDirectOnly,
    BleOnly,
    TorFallback,
}

data class BootstrapPeerHint(
    val peerHandle: String,
    val peerBootstrapToken: String,
    val peerDeviceId: String = "",
    val preference: BootstrapTransportPreference = BootstrapTransportPreference.WifiDirectBle,
)

data class TurnServerConfig(
    val urls: List<String>,
    val username: String = "",
    val credential: String = "",
)

data class TurnPolicy(
    val strategyName: String = "relay-assisted-turn",
    val servers: List<TurnServerConfig> = listOf(
        TurnServerConfig(listOf("stun:stun.l.google.com:19302")),
        TurnServerConfig(listOf("stun:stun.cloudflare.com:3478")),
    ),
    val forceRelayAfterFailures: Int = 2,
)

object TurnPolicyCodec {
    fun encode(policy: TurnPolicy): JSONObject = JSONObject()
        .put("strategyName", policy.strategyName)
        .put("forceRelayAfterFailures", policy.forceRelayAfterFailures)
        .put("servers", JSONArray().apply {
            policy.servers.forEach { server ->
                put(
                    JSONObject()
                        .put("urls", JSONArray(server.urls))
                        .put("username", server.username)
                        .put("credential", server.credential)
                )
            }
        })

    fun decode(json: JSONObject?): TurnPolicy? {
        if (json == null) return null
        val serversJson = json.optJSONArray("servers") ?: JSONArray()
        val servers = buildList {
            for (i in 0 until serversJson.length()) {
                val item = serversJson.optJSONObject(i) ?: continue
                val urlsJson = item.optJSONArray("urls") ?: JSONArray()
                val urls = buildList {
                    for (j in 0 until urlsJson.length()) {
                        urlsJson.optString(j).takeIf { it.isNotBlank() }?.let(::add)
                    }
                }
                add(
                    TurnServerConfig(
                        urls = urls,
                        username = item.optString("username"),
                        credential = item.optString("credential"),
                    )
                )
            }
        }
        return TurnPolicy(
            strategyName = json.optString("strategyName", "relay-assisted-turn"),
            servers = if (servers.isEmpty()) TurnPolicy().servers else servers,
            forceRelayAfterFailures = json.optInt("forceRelayAfterFailures", 2),
        )
    }
}
