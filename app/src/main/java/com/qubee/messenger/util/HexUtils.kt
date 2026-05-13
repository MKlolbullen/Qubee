package com.qubee.messenger.util

/**
 * Tiny hex helpers shared by the Contact/Identity layers. Extracted
 * here so callers in `ui/contacts` and `data/repository` don't have
 * to reach into each other's privates (or copy-paste the loop).
 */
object HexUtils {
    /**
     * Parse a hex string into its raw bytes. Throws on odd length
     * or non-hex characters — invariant in the Qubee identity space,
     * where ids are always 64 hex chars producing 32 bytes.
     */
    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "odd-length hex: ${hex.length}" }
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(hex[2 * i], 16)
            val lo = Character.digit(hex[2 * i + 1], 16)
            require(hi >= 0 && lo >= 0) { "non-hex char at index ${2 * i}" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}
