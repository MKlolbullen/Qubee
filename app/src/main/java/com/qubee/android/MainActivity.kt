package com.qubee.android

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    init {
        System.loadLibrary("qubee")
    }

    external fun encryptMessage(input: ByteArray): ByteArray

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Normally you’d setContentView here
    }
}
