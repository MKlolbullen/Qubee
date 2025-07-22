class OfflineQueue {
  private val queue = ConcurrentLinkedQueue<ByteArray>()

  fun enqueue(rawMsg: ByteArray) { queue.add(rawMsg) }
  fun flush() {
    while (queue.isNotEmpty()) {
      messagingClient.sendBinary(queue.poll())
    }
  }
}

// RekeyManager.kt
object RekeyManager {
  private var lastRekey = System.currentTimeMillis()

  fun considerRekey(batteryPct: Int, bandwidthKbps: Int) {
    val elapsed = System.currentTimeMillis() - lastRekey
    if (elapsed > 15 * 60_000 && batteryPct > 30 && bandwidthKbps > 50) {
      sessionKey = CryptoManager.generateKeyPair().public // rotate
      lastRekey = System.currentTimeMillis()
    }
  }
}
