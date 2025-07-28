package com.qubee.signaling

class RustSignaling {
    companion object {
        init {
            System.loadLibrary("qubee_crypto") // Loads libqubee_crypto.so
        }

        external fun encryptSignal(signal: String): String
    }

    fun sendEncryptedOffer(offer: String) {
        val encrypted = encryptSignal(offer)
        signalingClient.send(encrypted) // Replace with your actual signaling client
    }
}
