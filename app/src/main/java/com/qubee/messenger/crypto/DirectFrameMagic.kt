package com.qubee.messenger.crypto

/** Dispatch both durable v2 messages and v3 pool initials to Rust, including
 * malformed bodies: a recognized direct frame must never reach legacy decrypt. */
internal object DirectFrameMagic {
    private val prefix = "QUBEE_DMS".toByteArray(Charsets.US_ASCII)

    fun matches(data: ByteArray): Boolean =
        data.size > prefix.size && prefix.indices.all { data[it] == prefix[it] } &&
            (data[prefix.size] == 0x02.toByte() || data[prefix.size] == 0x03.toByte())
}
