package com.qubee.messenger.transfer

import android.content.Context
import android.content.Intent
import android.util.Base64
import android.webkit.MimeTypeMap
import androidx.core.content.FileProvider
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File

/**
 * A file is not a separate crypto scheme. It rides the same encrypted
 * 1:1 or group message as text, inside an application envelope the
 * receiver recognizes after decrypt. The identity of the peer is the
 * identity id, never a phone number.
 *
 * Raw size is capped so the sealed frame stays inside the direct-channel
 * and gossip transmit limits.
 */
object FileTransfer {
    const val MAX_BYTES: Int = 256 * 1024
    private const val MAX_NAME: Int = 120
    private const val MAX_BASE64: Int = ((MAX_BYTES + 2) / 3) * 4
    private const val MAGIC = "QUBEEFILE1\n"

    data class Decoded(val name: String, val bytes: ByteArray)

    /** Wraps `bytes` in the magic-tagged envelope sent as ordinary message text, or null if oversized/empty. */
    fun encode(name: String, bytes: ByteArray): String? {
        if (bytes.isEmpty() || bytes.size > MAX_BYTES) return null
        val safe = sanitize(name)
        val body = Base64.encodeToString(bytes, Base64.NO_WRAP)
        return MAGIC + safe + "\n" + body
    }

    /** Recognizes and unpacks a [FileTransfer] envelope from decrypted message text; null if it isn't one or fails validation. */
    fun decode(text: String): Decoded? {
        if (text.length > MAGIC.length + MAX_NAME + 1 + MAX_BASE64) return null
        if (!text.startsWith(MAGIC)) return null
        val rest = text.substring(MAGIC.length)
        val split = rest.indexOf('\n')
        if (split <= 0 || split > MAX_NAME) return null
        val name = rest.substring(0, split)
        if (name.any { it == '/' || it == '\\' || it.isISOControl() }) return null
        val body = rest.substring(split + 1)
        if (body.length > MAX_BASE64) return null
        val bytes = runCatching { Base64.decode(body, Base64.NO_WRAP) }.getOrNull() ?: return null
        if (bytes.isEmpty() || bytes.size > MAX_BYTES) return null
        return Decoded(name, bytes)
    }

    /** Persists a decoded attachment under `messageId`, encrypted at rest; false on any I/O or validation failure. */
    fun store(context: Context, messageId: String, decoded: Decoded): Boolean {
        if (!messageId.matches(Regex("[A-Za-z0-9-]{1,64}"))) return false
        if (decoded.bytes.isEmpty() || decoded.bytes.size > MAX_BYTES) return false
        return runCatching {
            val dir = File(context.filesDir, "transfers")
            if (!dir.exists() && !dir.mkdirs()) return false
            val destination = File(dir, messageId)
            if (destination.exists() && !destination.delete()) return false
            encryptedFile(context, destination).openFileOutput().use { it.write(decoded.bytes) }
            true
        }.getOrDefault(false)
    }

    /** Decrypts a stored attachment to a short-lived cache file and launches a viewer intent for it. */
    fun open(context: Context, messageId: String, displayName: String) {
        if (!messageId.matches(Regex("[A-Za-z0-9-]{1,64}"))) return
        Thread({
            runCatching {
                val encrypted = File(context.filesDir, "transfers/$messageId")
                if (!encrypted.isFile) return@runCatching
                val dir = File(context.cacheDir, "transfer-open")
                if (!dir.exists() && !dir.mkdirs()) return@runCatching
                val safeName = sanitize(displayName)
                val plaintext = File(dir, java.util.UUID.randomUUID().toString())
                // Schedule cleanup before decryption/viewer startup so their failures
                // cannot leave a partial plaintext export without a deletion task.
                android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(
                    { plaintext.delete() },
                    PLAINTEXT_CACHE_TTL_MS,
                )
                try {
                    encryptedFile(context, encrypted).openFileInput().use { input ->
                        plaintext.outputStream().use { output -> input.copyTo(output) }
                    }
                    val uri = FileProvider.getUriForFile(context, "${context.packageName}.files", plaintext)
                    val intent = Intent(Intent.ACTION_VIEW)
                        .setDataAndType(uri, mimeFor(safeName))
                        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(intent)
                } catch (error: Exception) {
                    plaintext.delete()
                    throw error
                }
            }.onFailure { timber.log.Timber.w(it, "Could not open encrypted transfer") }
        }, "qubee-transfer-open").start()
    }

    /** Remove prior viewer exports on process restart, including interrupted decrypts. */
    fun clearOpenCache(context: Context) {
        runCatching { File(context.cacheDir, "transfer-open").listFiles()?.forEach { it.delete() } }
    }

    /** Strips path separators/newlines from an attachment name and caps its length. */
    private fun sanitize(name: String): String {
        val cleaned = name.replace('\\', '_').replace('/', '_').replace('\n', '_')
            .replace('\r', '_')
            .map { if (it.isISOControl()) '_' else it }.joinToString("")
            .trim().ifBlank { "file" }
        return cleaned.take(MAX_NAME)
    }

    /** Guesses a MIME type from the file extension, defaulting to opaque binary. */
    private fun mimeFor(name: String): String {
        val ext = name.substringAfterLast('.', "")
        if (ext.isBlank() || ext == name) return "application/octet-stream"
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext.lowercase())
            ?: "application/octet-stream"
    }

    /** Builds the Keystore-backed [EncryptedFile] wrapper used for both storing and opening transfers. */
    private fun encryptedFile(context: Context, file: File): EncryptedFile {
        val key = MasterKey.Builder(context, MASTER_KEY_ALIAS)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedFile.Builder(
            context,
            file,
            key,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build()
    }

    private const val MASTER_KEY_ALIAS = "qubee_transfer_master_key"
    private const val PLAINTEXT_CACHE_TTL_MS = 10 * 60 * 1000L
}
