package com.qubee.messenger.data.database.dao

import androidx.room.*
import com.qubee.messenger.data.model.CryptoKey
import com.qubee.messenger.data.model.KeyType

@Dao
interface CryptoKeyDao {

    @Query("SELECT * FROM crypto_keys WHERE contactId = :contactId AND keyType = :keyType AND isActive = 1")
    suspend fun getActiveKeysForContact(contactId: String, keyType: KeyType): List<CryptoKey>

    @Query("SELECT * FROM crypto_keys WHERE contactId = :contactId AND keyType = :keyType ORDER BY createdAt DESC LIMIT 1")
    suspend fun getLatestKeyForContact(contactId: String, keyType: KeyType): CryptoKey?

    @Query("SELECT * FROM crypto_keys WHERE id = :keyId")
    suspend fun getKeyById(keyId: String): CryptoKey?

    @Query("SELECT * FROM crypto_keys WHERE contactId = :contactId")
    suspend fun getAllKeysForContact(contactId: String): List<CryptoKey>

    @Query("SELECT * FROM crypto_keys WHERE keyType = :keyType")
    suspend fun getKeysByType(keyType: KeyType): List<CryptoKey>

    @Query("SELECT * FROM crypto_keys WHERE expiresAt IS NOT NULL AND expiresAt <= :currentTime")
    suspend fun getExpiredKeys(currentTime: Long): List<CryptoKey>

    @Query("SELECT * FROM crypto_keys WHERE isActive = 0")
    suspend fun getInactiveKeys(): List<CryptoKey>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertKey(key: CryptoKey): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertKeys(keys: List<CryptoKey>)

    @Update
    suspend fun updateKey(key: CryptoKey)

    @Query("UPDATE crypto_keys SET isActive = :isActive WHERE id = :keyId")
    suspend fun updateKeyActiveStatus(keyId: String, isActive: Boolean)

    @Query("UPDATE crypto_keys SET isActive = 0 WHERE contactId = :contactId AND keyType = :keyType")
    suspend fun deactivateKeysForContact(contactId: String, keyType: KeyType)

    @Query("UPDATE crypto_keys SET expiresAt = :expiresAt WHERE id = :keyId")
    suspend fun updateKeyExpiration(keyId: String, expiresAt: Long?)

    @Delete
    suspend fun deleteKey(key: CryptoKey)

    @Query("DELETE FROM crypto_keys WHERE id = :keyId")
    suspend fun deleteKeyById(keyId: String)

    @Query("DELETE FROM crypto_keys WHERE contactId = :contactId")
    suspend fun deleteAllKeysForContact(contactId: String)

    @Query("DELETE FROM crypto_keys WHERE contactId = :contactId AND keyType = :keyType")
    suspend fun deleteKeysForContactByType(contactId: String, keyType: KeyType)

    @Query("DELETE FROM crypto_keys WHERE expiresAt IS NOT NULL AND expiresAt <= :currentTime")
    suspend fun deleteExpiredKeys(currentTime: Long): Int

    @Query("DELETE FROM crypto_keys WHERE isActive = 0 AND createdAt <= :beforeTime")
    suspend fun deleteOldInactiveKeys(beforeTime: Long): Int

    @Query("SELECT COUNT(*) FROM crypto_keys WHERE contactId = :contactId")
    suspend fun getKeyCountForContact(contactId: String): Int

    @Query("SELECT COUNT(*) FROM crypto_keys WHERE keyType = :keyType")
    suspend fun getKeyCountByType(keyType: KeyType): Int

    @Query("SELECT COUNT(*) FROM crypto_keys WHERE isActive = 1")
    suspend fun getActiveKeyCount(): Int
}

