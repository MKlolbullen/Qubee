class MediaSender(private val sessionKey: ByteArray) {
  fun sendFile(file: File, progress: (Float) -> Unit) {
    file.inputStream().use { fis ->
      val buffer = ByteArray(4096)
      var read: Int
      while (fis.read(buffer).also { read = it } > 0) {
        val encrypted = AESGCM.encrypt(buffer, sessionKey)
        uploadChunk(encrypted)
        progress(fis.available().toFloat() / file.length())
      }
    }
  }

  fun sendVoiceNote(recording: ByteArray) {
    val compressed = Zstd.compress(recording)
    val encrypted  = AESGCM.encrypt(compressed, sessionKey)
    messagingClient.sendBinary(encrypted)
  }

  private fun uploadChunk(chunk: ByteArray) {
    // POST chunk to server’s chunk endpoint
  }
}
