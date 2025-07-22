enum class SignatureScheme { DILITHIUM_3, FALCON_512 }

// CryptoManager.kt
object CryptoManager {
    init { System.loadLibrary("qubee_crypto") }

    // Swap to a different post-quantum signature scheme at runtime
    fun swapSignatureScheme(scheme: SignatureScheme) {
        pqCryptoSwapScheme(scheme.name)
    }

    // Generate a new PQ keypair
    fun generateKeyPair(): KeyPair {
        val raw = pqCryptoGenerateKeyPair()            // JNI call returns concatenated pub||priv
        return KeyPair(public = raw.copyOfRange(0,    pubLen),
                       private = raw.copyOfRange(pubLen, raw.size))
    }

    // Sign message bytes
    fun sign(message: ByteArray, privateKey: ByteArray): ByteArray =
        pqCryptoSign(message, privateKey)

    // Verify signature
    fun verify(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean =
        pqCryptoVerify(message, signature, publicKey)

    // Native JNI bindings
    private external fun pqCryptoSwapScheme(scheme: String)
    private external fun pqCryptoGenerateKeyPair(): ByteArray
    private external fun pqCryptoSign(msg: ByteArray, priv: ByteArray): ByteArray
    private external fun pqCryptoVerify(msg: ByteArray, sig: ByteArray, pub: ByteArray): Boolean
}
