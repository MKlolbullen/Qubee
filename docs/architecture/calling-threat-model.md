# Calling threat model

Status: **gated research surface.** The default native library is built
without `--features calling`, and `BuildConfig.CALLING_NATIVE_ENABLED`
is false unless Gradle is invoked with `-PqubeeCalling=true`. A default
APK must not present a call control. Video capture/rendering are integrated
behind the build gate but remain unvalidated on physical devices. Calling
startup also remains blocked by the relay-only signaling gate below.
Nothing in this document is a ship claim.

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

For a 1:1 call both endpoints export a fresh 32-byte media root from the
exact Double Ratchet message key that encrypts the invitation. The exporter
is BLAKE3 keyed by that message key over `qubee_call_media_root_v1\0`,
the 16-byte call id, the little-endian u64 conversation-AD length, and
the conversation AD. It does not retain the PQXDH initial secret or expose
the current ratchet root, which need not agree across endpoints.

All signaling frames use the `qubee_call_signal_v2\0` prefix followed by
fixed-integer bincode. The unversioned legacy codec is rejected: its random-root
semantics cannot interoperate with exporter-derived roots. The invitation
retains the `media_root` field, but Rust sends zeros and ignores any peer-supplied
value. Decrypt exports only
after AEAD authentication, including when consuming a skipped message key,
and substitutes the derived root locally before the call state machine runs.
Rust provisions the caller's root before handing encrypted wire bytes to
Android; Android sends those bytes unchanged, without encrypting them again. Both
endpoints derive the same per-call media key from that root, the call
id, and the canonical sorted participant pair.

Retry delivery of the same encrypted invitation wire bytes only. Do not
re-encrypt an invitation: that consumes another message key and exports a
different root, while a live call deliberately rejects root replacement.
Outbound encryption/provisioning failures emit the existing call-error event
to Android rather than leaving the UI silently waiting.

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

An all-zero provisioned media root is rejected (the wire placeholder is
replaced before this check). A replayed invitation does not
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
| Video RTP payload | 1..=16 KiB. Video hardware validation is pending |
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

- The calling configuration now defaults to `RelayOnly` with no public
  STUN servers. It rejects a missing TURN allocation/credentials instead
  of silently trying direct ICE. `RTCIceTransportPolicy::Relay` is set in
  webrtc-rs; trickle and inline SDP candidates are checked as a second
  boundary. Related-address attributes are removed from relay candidates.
- `DirectDevelopment` is an explicit test-only policy. It exposes host and
  server-reflexive addresses; it must not be wired into an Android release.
- TURN is not provisioned by default. Its operator still sees the client's
  IP, allocations, timing, and traffic volume. It cannot read DTLS-SRTP
  media content. Credentials should be short-lived and identity-opaque;
  credential provisioning is not yet implemented.
- **Call signaling still uses the direct libp2p message path.** A media-only
  TURN policy cannot hide the peer IP while that path exists. Android
  `nativeStartCalling` therefore fails closed until the signaling transport
  is relay-only and tested. Existing ordinary chat traffic retains its
  documented direct-network metadata behavior.
- DTLS-SRTP protects media contents from the path. It does not hide that
  a media flow exists, its timing, or its volume.
- A relay operator sees the client IP and allocation times. A peer receiving
  relay ICE candidates learns the relay's address, but any simultaneously
  connected direct Qubee chat/libp2p session still reveals the client's IP.
- A direct inbox topic rotates but is derivable from the public IdentityId
  and epoch. A party knowing that ID can monitor topic activity. Neither
  topic blinding nor signaling encryption hides that party's traffic timing.
- Android logcat previously included call IDs and peer IdentityIds on the
  call path. The calling diagnostics now log only event classes and call
  state; other network and chat diagnostics still require a separate audit.
- Tor and Nym are not transports for this path. Enabling calling does
  not anonymise the peer.

No end-to-end IP-anonymity claim follows from relay-only ICE. The relay
and traffic observer still see timing and volume, and the direct message
transport must be redesigned before calling can be enabled.

Decentralisation is a deployment and trust choice, not a guarantee of IP
anonymity. Two endpoints can keep their existing end-to-end encryption and
session keys while routing via independently operated relays. A direct
peer-to-peer mode can be offered later only as an explicit IP-sharing choice
for *both* endpoints; it must never be a silent fallback from a private
mode. A single mandatory Coturn host would concentrate metadata even if it
cannot decrypt media. Federation or user-selected relays require separate
discovery, authentication, abuse limits, and cross-relay interoperability
work; none are implemented yet.

Release gates for metadata: provision TURN at runtime, relay the complete
1:1 signaling session without direct libp2p dialing/address advertisement,
prove packet-capture absence of direct peer traffic including reconnection
and ICE restart, then run the physical device matrix. Do not merely flip
the Android guard or add TURN credentials to the APK.
The observer-by-observer risks, exact physical cases and first Samsung run
are in [calling-metadata-matrix.md](calling-metadata-matrix.md).

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
- Video capture and rendering must remain gated until voice is stable on
  hardware, then be validated on physical devices.
