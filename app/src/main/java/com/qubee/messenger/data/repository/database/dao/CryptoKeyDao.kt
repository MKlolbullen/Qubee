package com.qubee.messenger.data.repository.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.qubee.messenger.data.model.CryptoKey
import com.qubee.messenger.data.model.KeyType

// Note: The cryptographic *secret* material lives in the Rust
// SecureKeyStore (XChaCha20-Poly1305 + BLAKE3-MAC). This DAO holds
// derived metadata + public-key bookkeeping that the UI needs to
// reason about (which contacts are verified, when keys rotated,
// etc.). Don't store identity or group-key secrets here.
@Dao
interface CryptoKeyDao {

    @Query("SELECT * FROM crypto_keys WHERE contactId = :contactId AND isActive = 1")
    suspend fun getActiveKeysForContact(contactId: String): List<CryptoKey>

    @Query("SELECT * FROM crypto_keys WHERE contactId = :contactId ORDER BY createdAt DESC LIMIT 1")
    suspend fun getLatestKeyForContact(contactId: String): CryptoKey?

    @Query("SELECT * FROM crypto_keys WHERE id = :keyId")
    suspend fun getKeyById(keyId: String): CryptoKey?

    @Query("SELECT * FROM crypto_keys WHERE contactId = :contactId")
    suspend fun getAllKeysForContact(contactId: String): List<CryptoKey>

    @Query("SELECT * FROM crypto_keys WHERE keyType = :keyType")
    suspend fun getKeysByType(keyType: KeyType): List<CryptoKey>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertKey(key: CryptoKey)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertKeys(keys: List<CryptoKey>)

    @Update
    suspend fun updateKey(key: CryptoKey)

    @Query("UPDATE crypto_keys SET isActive = :isActive WHERE id = :keyId")
    suspend fun updateKeyActiveStatus(keyId: String, isActive: Boolean)

    @Query("UPDATE crypto_keys SET isActive = 0 WHERE contactId = :contactId")
    suspend fun deactivateKeysForContact(contactId: String)

    @Query("DELETE FROM crypto_keys WHERE id = :keyId")
    suspend fun deleteKeyById(keyId: String)

    @Query("DELETE FROM crypto_keys WHERE contactId = :contactId")
    suspend fun deleteAllKeysForContact(contactId: String)

    @Query("DELETE FROM crypto_keys WHERE expiresAt IS NOT NULL AND expiresAt < :nowSeconds")
    suspend fun deleteExpiredKeys(nowSeconds: Long): Int
}
