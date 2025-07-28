package com.qubee.messenger.crypto

import java.nio.ByteBuffer
import java.util.Date

/**
 * Represents an identity key pair for post-quantum cryptography
 */
data class IdentityKeyPair(
    val publicKey: ByteArray,
    val privateKey: ByteArray,
    val createdAt: Date = Date()
) {
    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(4 + publicKey.size + 4 + privateKey.size + 8)
        buffer.putInt(publicKey.size)
        buffer.put(publicKey)
        buffer.putInt(privateKey.size)
        buffer.put(privateKey)
        buffer.putLong(createdAt.time)
        return buffer.array()
    }

    companion object {
        fun fromBytes(bytes: ByteArray): IdentityKeyPair? {
            return try {
                val buffer = ByteBuffer.wrap(bytes)
                val publicKeySize = buffer.int
                val publicKey = ByteArray(publicKeySize)
                buffer.get(publicKey)
                
                val privateKeySize = buffer.int
                val privateKey = ByteArray(privateKeySize)
                buffer.get(privateKey)
                
                val timestamp = buffer.long
                val createdAt = Date(timestamp)
                
                IdentityKeyPair(publicKey, privateKey, createdAt)
            } catch (e: Exception) {
                null
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IdentityKeyPair

        if (!publicKey.contentEquals(other.publicKey)) return false
        if (!privateKey.contentEquals(other.privateKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + privateKey.contentHashCode()
        return result
    }
}

/**
 * Represents ephemeral keys used for key exchange
 */
data class EphemeralKeyPair(
    val publicKey: ByteArray,
    val privateKey: ByteArray,
    val createdAt: Date = Date()
) {
    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(4 + publicKey.size + 4 + privateKey.size + 8)
        buffer.putInt(publicKey.size)
        buffer.put(publicKey)
        buffer.putInt(privateKey.size)
        buffer.put(privateKey)
        buffer.putLong(createdAt.time)
        return buffer.array()
    }

    companion object {
        fun fromBytes(bytes: ByteArray): EphemeralKeyPair? {
            return try {
                val buffer = ByteBuffer.wrap(bytes)
                val publicKeySize = buffer.int
                val publicKey = ByteArray(publicKeySize)
                buffer.get(publicKey)
                
                val privateKeySize = buffer.int
                val privateKey = ByteArray(privateKeySize)
                buffer.get(privateKey)
                
                val timestamp = buffer.long
                val createdAt = Date(timestamp)
                
                EphemeralKeyPair(publicKey, privateKey, createdAt)
            } catch (e: Exception) {
                null
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EphemeralKeyPair

        if (!publicKey.contentEquals(other.publicKey)) return false
        if (!privateKey.contentEquals(other.privateKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + privateKey.contentHashCode()
        return result
    }
}

/**
 * Represents a hybrid ratchet session
 */
data class RatchetSession(
    val sessionId: String,
    val contactId: String,
    val sessionData: ByteArray,
    val createdAt: Date = Date(),
    val lastUsed: Date = Date()
) {
    fun toBytes(): ByteArray {
        val sessionIdBytes = sessionId.toByteArray()
        val contactIdBytes = contactId.toByteArray()
        
        val buffer = ByteBuffer.allocate(
            4 + sessionIdBytes.size +
            4 + contactIdBytes.size +
            4 + sessionData.size +
            8 + 8
        )
        
        buffer.putInt(sessionIdBytes.size)
        buffer.put(sessionIdBytes)
        buffer.putInt(contactIdBytes.size)
        buffer.put(contactIdBytes)
        buffer.putInt(sessionData.size)
        buffer.put(sessionData)
        buffer.putLong(createdAt.time)
        buffer.putLong(lastUsed.time)
        
        return buffer.array()
    }

    companion object {
        fun fromBytes(bytes: ByteArray): RatchetSession? {
            return try {
                val buffer = ByteBuffer.wrap(bytes)
                
                val sessionIdSize = buffer.int
                val sessionIdBytes = ByteArray(sessionIdSize)
                buffer.get(sessionIdBytes)
                val sessionId = String(sessionIdBytes)
                
                val contactIdSize = buffer.int
                val contactIdBytes = ByteArray(contactIdSize)
                buffer.get(contactIdBytes)
                val contactId = String(contactIdBytes)
                
                val sessionDataSize = buffer.int
                val sessionData = ByteArray(sessionDataSize)
                buffer.get(sessionData)
                
                val createdAtTimestamp = buffer.long
                val lastUsedTimestamp = buffer.long
                
                RatchetSession(
                    sessionId,
                    contactId,
                    sessionData,
                    Date(createdAtTimestamp),
                    Date(lastUsedTimestamp)
                )
            } catch (e: Exception) {
                null
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RatchetSession

        if (sessionId != other.sessionId) return false
        if (contactId != other.contactId) return false
        if (!sessionData.contentEquals(other.sessionData)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = sessionId.hashCode()
        result = 31 * result + contactId.hashCode()
        result = 31 * result + sessionData.contentHashCode()
        return result
    }
}

/**
 * Represents an encrypted message
 */
data class EncryptedMessage(
    val ciphertext: ByteArray,
    val header: ByteArray,
    val signature: ByteArray,
    val timestamp: Date = Date()
) {
    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(
            4 + ciphertext.size +
            4 + header.size +
            4 + signature.size +
            8
        )
        
        buffer.putInt(ciphertext.size)
        buffer.put(ciphertext)
        buffer.putInt(header.size)
        buffer.put(header)
        buffer.putInt(signature.size)
        buffer.put(signature)
        buffer.putLong(timestamp.time)
        
        return buffer.array()
    }

    companion object {
        fun fromBytes(bytes: ByteArray): EncryptedMessage? {
            return try {
                val buffer = ByteBuffer.wrap(bytes)
                
                val ciphertextSize = buffer.int
                val ciphertext = ByteArray(ciphertextSize)
                buffer.get(ciphertext)
                
                val headerSize = buffer.int
                val header = ByteArray(headerSize)
                buffer.get(header)
                
                val signatureSize = buffer.int
                val signature = ByteArray(signatureSize)
                buffer.get(signature)
                
                val timestampValue = buffer.long
                val timestamp = Date(timestampValue)
                
                EncryptedMessage(ciphertext, header, signature, timestamp)
            } catch (e: Exception) {
                null
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptedMessage

        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (!header.contentEquals(other.header)) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ciphertext.contentHashCode()
        result = 31 * result + header.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

/**
 * Represents an encrypted file
 */
data class EncryptedFile(
    val encryptedData: ByteArray,
    val key: ByteArray,
    val iv: ByteArray,
    val hash: ByteArray,
    val originalSize: Long,
    val timestamp: Date = Date()
) {
    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(
            4 + encryptedData.size +
            4 + key.size +
            4 + iv.size +
            4 + hash.size +
            8 + 8
        )
        
        buffer.putInt(encryptedData.size)
        buffer.put(encryptedData)
        buffer.putInt(key.size)
        buffer.put(key)
        buffer.putInt(iv.size)
        buffer.put(iv)
        buffer.putInt(hash.size)
        buffer.put(hash)
        buffer.putLong(originalSize)
        buffer.putLong(timestamp.time)
        
        return buffer.array()
    }

    companion object {
        fun fromBytes(bytes: ByteArray): EncryptedFile? {
            return try {
                val buffer = ByteBuffer.wrap(bytes)
                
                val encryptedDataSize = buffer.int
                val encryptedData = ByteArray(encryptedDataSize)
                buffer.get(encryptedData)
                
                val keySize = buffer.int
                val key = ByteArray(keySize)
                buffer.get(key)
                
                val ivSize = buffer.int
                val iv = ByteArray(ivSize)
                buffer.get(iv)
                
                val hashSize = buffer.int
                val hash = ByteArray(hashSize)
                buffer.get(hash)
                
                val originalSize = buffer.long
                val timestampValue = buffer.long
                val timestamp = Date(timestampValue)
                
                EncryptedFile(encryptedData, key, iv, hash, originalSize, timestamp)
            } catch (e: Exception) {
                null
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptedFile

        if (!encryptedData.contentEquals(other.encryptedData)) return false
        if (!key.contentEquals(other.key)) return false
        if (!iv.contentEquals(other.iv)) return false
        if (!hash.contentEquals(other.hash)) return false
        if (originalSize != other.originalSize) return false

        return true
    }

    override fun hashCode(): Int {
        var result = encryptedData.contentHashCode()
        result = 31 * result + key.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + hash.contentHashCode()
        result = 31 * result + originalSize.hashCode()
        return result
    }
}

