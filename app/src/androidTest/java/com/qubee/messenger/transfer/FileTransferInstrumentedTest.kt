package com.qubee.messenger.transfer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FileTransferInstrumentedTest {
    @Test
    fun maximumAttachmentRoundTripsAndOversizeIsRejected() {
        val bytes = ByteArray(FileTransfer.MAX_BYTES) { (it % 251).toByte() }
        val encoded = requireNotNull(FileTransfer.encode("document.pdf", bytes))
        val decoded = requireNotNull(FileTransfer.decode(encoded))
        assertEquals("document.pdf", decoded.name)
        assertArrayEquals(bytes, decoded.bytes)
        assertNull(FileTransfer.encode("large", ByteArray(FileTransfer.MAX_BYTES + 1)))
        assertNull(FileTransfer.decode("QUBEEFILE1\nlarge\n" + "A".repeat(encoded.length)))
    }

    @Test
    fun unsafeNamesAndMalformedBase64AreRejected() {
        for (name in listOf("../private", "path\\file", "file\u0000name", "file\rname")) {
            assertNull(FileTransfer.decode("QUBEEFILE1\n$name\nYQ=="))
        }
        assertNull(FileTransfer.decode("QUBEEFILE1\nfile\n!"))
        assertNull(FileTransfer.decode("QUBEEFILE1\nfile\n"))
    }

    @Test
    fun directStoreCannotBypassSizeValidation() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertFalse(FileTransfer.store(context, "invalid-empty", FileTransfer.Decoded("file", byteArrayOf())))
        assertFalse(FileTransfer.store(context, "invalid-large", FileTransfer.Decoded("file", ByteArray(FileTransfer.MAX_BYTES + 1))))
    }

    @Test
    fun storedAttachmentContainsCiphertext() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val messageId = java.util.UUID.randomUUID().toString()
        val file = File(context.filesDir, "transfers/$messageId")
        val secret = "distinctive-private-attachment-content".toByteArray()
        try {
            assertTrue(FileTransfer.store(context, messageId, FileTransfer.Decoded("private.txt", secret)))
            val stored = file.readBytes().toString(Charsets.ISO_8859_1)
            assertFalse(stored.contains(secret.toString(Charsets.ISO_8859_1)))
        } finally {
            file.delete()
        }
    }

    @Test
    fun startupCleanupRemovesInterruptedPlaintextExports() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val directory = File(context.cacheDir, "transfer-open").apply { mkdirs() }
        val interrupted = File(directory, java.util.UUID.randomUUID().toString())
        interrupted.writeText("interrupted viewer export")
        FileTransfer.clearOpenCache(context)
        assertFalse(interrupted.exists())
        FileTransfer.clearOpenCache(context) // also safe on an empty cache
    }
}
