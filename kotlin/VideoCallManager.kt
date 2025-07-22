class VideoCallManager(private val context: Context) {
    private lateinit var peerConnection: PeerConnection
    private lateinit var localVideoTrack: VideoTrack
    private lateinit var remoteVideoTrack: VideoTrack

    fun startCall() {
        val eglBase = EglBase.create()
        val factory = PeerConnectionFactory.builder().createPeerConnectionFactory()

        val videoCapturer = createCameraCapturer()
        val videoSource = factory.createVideoSource(videoCapturer.isScreencast)
        videoCapturer.initialize(SurfaceTextureHelper.create("CaptureThread", eglBase.eglBaseContext), context, videoSource.capturerObserver)
        videoCapturer.startCapture(1280, 720, 30)

        localVideoTrack = factory.createVideoTrack("LOCAL_VIDEO", videoSource)
        peerConnection = factory.createPeerConnection(peerConfig(), object : PeerConnection.Observer {
            override fun onAddStream(stream: MediaStream?) {
                remoteVideoTrack = stream?.videoTracks?.get(0)!!
                // Attach to remote view
            }
            // Handle ICE, signaling, etc.
        })!!

        val stream = factory.createLocalMediaStream("LOCAL_STREAM")
        stream.addTrack(localVideoTrack)
        peerConnection.addStream(stream)
    }

    private fun peerConfig(): PeerConnection.RTCConfiguration {
        val iceServers = listOf(PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer())
        return PeerConnection.RTCConfiguration(iceServers)
    }

    private fun createCameraCapturer(): CameraVideoCapturer {
        val enumerator = Camera2Enumerator(context)
        val deviceNames = enumerator.deviceNames
        for (name in deviceNames) {
            if (enumerator.isFrontFacing(name)) {
                return enumerator.createCapturer(name, null)!!
            }
        }
        throw IllegalStateException("No front camera found")
    }
}
