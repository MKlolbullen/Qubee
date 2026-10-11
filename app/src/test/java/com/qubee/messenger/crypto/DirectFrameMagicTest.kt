package com.qubee.messenger.crypto

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DirectFrameMagicTest {
    @Test fun versionsAndMalformedBodiesStayOnTheDirectPath() {
        val prefix = "QUBEE_DMS".toByteArray(Charsets.US_ASCII)
        assertTrue(DirectFrameMagic.matches(prefix + byteArrayOf(2)))
        assertTrue(DirectFrameMagic.matches(prefix + byteArrayOf(3, -1)))
        assertFalse(DirectFrameMagic.matches(prefix))
        assertFalse(DirectFrameMagic.matches(prefix + byteArrayOf(1)))
        assertFalse(DirectFrameMagic.matches(prefix + byteArrayOf(4)))
        assertFalse(DirectFrameMagic.matches("QUBEE_GMS".toByteArray() + byteArrayOf(3)))
    }
}
