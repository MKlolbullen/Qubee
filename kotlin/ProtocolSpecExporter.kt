object ProtocolSpecExporter {
  fun exportAsMarkdown(): String {
    return """
      # Qubee Protocol v1.0
      ## Handshake
      1. Client → Server: ClientHello(pubKey, timestamp)
      2. Server → Client: ServerHello(pubKey, timestamp) + signature
      ## Message Frame
      - sequence: uint32
      - payload: bytes
      - mac: bytes
      ...
    """.trimIndent()
  }
}
