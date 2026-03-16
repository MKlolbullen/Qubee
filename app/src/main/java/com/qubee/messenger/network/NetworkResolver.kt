package com.qubee.messenger.network

import kotlinx.coroutines.flow.Flow

data class NetworkEndpoint(
    val ipAddress: String,
    val port: Int,
    val publicKey: ByteArray // För att verifiera att vi hittat rätt person
)

interface NetworkResolver {
    /**
     * Publicera vår egen närvaro i nätverket så andra kan hitta oss.
     * @param myId Vårt UUID eller Publika nyckelhash
     */
    suspend fun announcePresence(myId: String, port: Int)

    /**
     * Leta upp en IP-adress baserat på ett ID.
     * Detta kan söka via DHT, mDNS eller Bluetooth.
     */
    suspend fun resolvePeer(userId: String): NetworkEndpoint?
}
