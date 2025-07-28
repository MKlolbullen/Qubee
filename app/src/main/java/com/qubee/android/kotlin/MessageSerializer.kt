object MessageSerializer {
  fun serialize(msg: ChatMessage): ByteArray {
    val proto  = QubeeProto.ChatMessage.newBuilder()
      .setSender(msg.sender)
      .setTimestamp(msg.timestamp)
      .setPayload(ByteString.copyFrom(msg.payload))
      .build()
    return Zstd.compress(proto.toByteArray())
  }

  fun deserialize(raw: ByteArray): ChatMessage {
    val decompressed = Zstd.decompress(raw, MAX_MSG_SIZE)
    val proto        = QubeeProto.ChatMessage.parseFrom(decompressed)
    return ChatMessage(
      sender   = proto.sender,
      timestamp= proto.timestamp,
      payload  = proto.payload.toByteArray()
    )
  }
}
