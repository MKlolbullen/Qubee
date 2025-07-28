object PrivacyUtils {
  fun applySelfDestruct(timerSeconds: Int, messageId: String) {
    Handler(Looper.getMainLooper()).postDelayed({
      messagingClient.deleteMessageLocally(messageId)
    }, timerSeconds * 1000L)
  }

  fun blurImage(bitmap: Bitmap, radius: Float = 25f): Bitmap {
    val render = RenderScript.create(appContext)
    val inp    = Allocation.createFromBitmap(render, bitmap)
    val out    = Allocation.createTyped(render, inp.type)
    val script = ScriptIntrinsicBlur.create(render, Element.U8_4(render))
    script.setRadius(radius)
    script.setInput(inp)
    script.forEach(out)
    out.copyTo(bitmap)
    return bitmap
  }
}
