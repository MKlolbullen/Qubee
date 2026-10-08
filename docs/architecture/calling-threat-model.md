# Calling threat model

Status: **gated research surface.** The default native library is built
without `--features calling`, and `BuildConfig.CALLING_NATIVE_ENABLED`
is false unless Gradle is invoked with `-PqubeeCalling=true`. A default
APK must not present a call control. Video capture and rendering are
not implemented. Nothing in this document is a ship claim.

## Addressing

A Qubee call is an encrypted media session between cryptographic
identities, in the same sense as a Signal or Threema call. It is not a
PSTN, cellular, or SIP phone call.

The only peer identifier on this path is a 32-byte `IdentityId`. There
is no phone number, MSISDN, IMSI, IMEI, SIP URI, or carrier caller-ID
in the invitation, the SDP, the ICE exchange, or the JNI methods. A
string that is not 32 bytes of hex is not a peer and must be rejected
before a session is created. The app does not read the device phone
book to decide who can be reached.

STUN and TURN, when configured, learn network addresses. Those are IP
metadata, not telephone identifiers. See the metadata section below.

## Media-security boundary

For a 1:1 call the caller mints a fresh 32-byte media root and sends it
inside the authenticated, end-to-end encrypted call invitation. Both
endpoints derive the same per-call media key from that root, the call
id, and the canonical sorted participant pair.

That derivation is **not** a second media encryption layer on the wire.

What actually protects encoded media today:

- WebRTC negotiates **DTLS-SRTP**. `WebRTCConfig` enables both.
- The in-tree `MediaEncryption` / `MediaKey` helpers can encrypt a frame
  with ChaCha20-Poly1305, and tests prove the two endpoints derive the
  same key. The Android sample path does **not** call them.
  `write_audio_sample` packetizes the Opus bitstream the app already
  encoded and hands it to webrtc-rs. Remote RTP payloads are forwarded
  to the app for decode. There is no application-layer frame encryption
  on that path.

Do not document both DTLS-SRTP and Qubee frame encryption as active.
Secrecy of the media root reduces to the established 1:1 session. A
separate contributory media handshake is future work, not current
behavior.

An all-zero media root is rejected. A replayed invitation does not
replace a live root and does not re-ring a call that has ended,
been rejected, or timed out.

## Authenticated signaling

Call frames ride the decrypted 1:1 session. The session peer (`from`)
is the only identity the frame may name. An embedded `caller` or
`sender` that does not match `from` is rejected. ICE, SDP, and hang-up
frames for a call that peer is not in are not applied to any other
call, and ICE for an unknown call is not cached.

## Resource bounds

| Boundary | Policy |
|---|---|
| Inbound signaling blob | Reject above 64 KiB before bincode allocation |
| SDP offer/answer | Reject empty or above 32 KiB |
| ICE candidate text | Reject above 1 KiB; cache at most 16 per peer |
| Audio frame (RTP or app sample) | 1..=2048 bytes. Opus itself is at most 1275 |
| Video RTP payload | 1..=16 KiB. Video capture is not shipped |
| Remote media queue | 12 frames, drop oldest. Same window as Android playback |
| Live calls | `max_concurrent_calls`, rechecked under the write lock |

The remote-media queue is the buffer the playback drain reads. Frames
are not copied into the unbounded call-event channel first. A slow
decoder therefore cannot be used to grow Rust memory without bound.

## Codec

Android capture is 48 kHz mono Opus (`AudioCallEngine`). The WebRTC
media engine registers that profile (`opus/48000/1`, `stereo=0`,
`sprop-stereo=0`). It does not call `register_default_codecs()`, whose
Opus entry is stereo and would stay in the offer if registered first.
`AudioQuality` preferences do not override this. Stereo is not
advertised until an encoder that emits stereo is actually wired.

## Metadata: ICE, STUN, and TURN

Calling does not hide network location.

- The default configuration lists public STUN servers
  (`stun.l.google.com`, `stun1.l.google.com`). A STUN binding request
  tells that server the reflexive address of this device.
- ICE candidates exchanged with the peer include host and server-reflexive
  addresses. The peer, and anyone who can read the signaling session,
  learns those addresses. Signaling is encrypted, so a passive network
  observer of the Qubee session does not see the candidate strings, but
  the STUN/TURN servers and the eventual media path do see IP traffic.
- TURN is supported as configuration and is empty by default. If a TURN
  server is configured, that relay sees the client's allocations and the
  media it forwards. TURN credentials in `TurnServer` are call-setup
  configuration, not a substitute for the media key.
- DTLS-SRTP protects media contents from the path. It does not hide that
  a media flow exists, its timing, or its volume.
- Tor and Nym are not transports for this path. Enabling calling does
  not anonymise the peer.

Treat a call as a direct network exposure to the peer and to whatever
STUN/TURN infrastructure the build was configured with. That is a
stronger metadata leak than an ordinary direct message, which already
exposes the peer's libp2p address.

## Teardown

`CallMediaService.stop` clears the desired call id and stops
`AudioCallEngine` before `stopService` returns. A start command that
was already queued sees the cleared id and does not reopen the
microphone. `AudioCallEngine.stop` is idempotent and releases
`AudioRecord`, the encoder, the decoder, and `AudioTrack`. This is
still unproven on API 34+ foreground-service and permission races.

## Still required before a release claim

- Two physical phones, near-AOSP plus at least one aggressive OEM.
- API 34+ microphone foreground-service start and `RECORD_AUDIO` timing.
- Codec availability across those devices.
- Wi-Fi to cellular, ICE restart, backgrounding, long-call memory,
  thermal, and battery.
- Echo cancellation, noise suppression, and gain. The settings flags
  exist; the peer-connection methods are stubs.
- Video capture and rendering only after the voice path is stable on
  hardware.
