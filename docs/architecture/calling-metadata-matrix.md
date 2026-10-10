# Calling metadata and physical-device gates (#79)

Status: calling is disabled in the standard APK and blocked at native startup
until the complete signaling path is relayed and validated. PR #86's relay-only
ICE policy and TURN staging, and PR #91's authenticated encrypted signaling and
session-derived media roots, are merged; neither provides physical-device proof
or removes the direct libp2p metadata exposure. Host tests do not prove the
absence of address leaks on two physical phones.

## Observation points

| Observer | What it can learn today | Reduction and remaining limit |
|---|---|---|
| Remote peer or malicious contact | Direct libp2p TCP/QUIC source IP, PeerId, connection times; if direct ICE were enabled, host/reflexive addresses | Relay the **entire** 1:1 transport and use relay-only ICE for an IP-private mode. Direct P2P remains an explicit IP-sharing mode only after a separate design and consent flow. A peer always knows it is in the conversation. |
| Bootstraps, DHT nodes and gossip neighbors | IP/PeerId and query, subscription or routing timing; Kademlia server may advertise addresses | mDNS is off by default; client-mode Kademlia is opt-in and costs discoverability. A private mode must not run a simultaneous direct node or announce its public addresses. Anonymous gossip removes an author field but cannot prevent correlation by a connected neighbor. |
| Anyone who knows a Qubee IdentityId and subscribes to its inbox topics | Deterministic epoch topic labels, publication timing and ciphertext lengths; can attempt spam | Ratchet encryption protects content, padding reduces length precision. Topic labels are **not secret** from holders of the public ID. Private rendezvous needs a separately designed shared secret or capability, including first contact and rotation. |
| TURN or signaling relay operator | Client IP, allocations, routing, session timing, byte counts and potentially peer linkage | Short-lived opaque credentials, minimal volatile logs, independently operated or user-selected relays. A relay cannot be promised blindness to source IP. E2EE/DTLS-SRTP protects content from it; additional media frame encryption is not wired. |
| ISP, Wi-Fi operator or global traffic observer | Server/peer IP, protocol/port, call duration, packet sizes, traffic bursts and network transitions | Relay hides the remote endpoint address from a local observer if all traffic uses relay, but still exposes relay IP and timing. Padding and cover traffic are future work; no traffic-analysis resistance is claimed. |
| Device owner, malware, logcat/backup collector | Call IDs, peer identifiers and state if written to logs; microphone/camera indicators | Call-path diagnostics omit IDs, but OS, chat logs, crash reports and a compromised endpoint remain outside this fix. Inspect release logcat and Android backups. |

A TCP wrapper or TLS proxy changes the hop that sees packets; it cannot make
the endpoint's source IP disappear. Peer-to-peer describes the session and
end-to-end key ownership, not a requirement for a direct IP path. Multiple
community or self-hosted relays avoid a mandatory Qubee operator but do not
magically erase relay metadata.

## Priority and evidence

Record phone model, Android version, app commit/build flags, network provider,
relay host/version, time window, sanitized packet-capture hashes, logs with
IDs redacted, result and reproducible issue link for each row. Capture on
both device/VPN interface and relay where possible; a single relay log cannot
prove absence of direct packets. Use controlled peer addresses so captures
can distinguish peer, TURN and bootstrap traffic. Do not publish raw IPs,
credentials, SDP or device identifiers in an issue.

| Priority / case | Procedure on two physical phones | Pass condition |
|---|---|---|
| P0 / G0 build gate | Install standard build; inspect call controls and attempt native calling entry point | No usable call control or media capture; capability reflects disabled feature. |
| P0 / G1 private path | On isolated test accounts, establish a chat session, then a call with independently observed peer IPs; capture setup, steady state and teardown | No phone-to-phone TCP/UDP, no peer address advertisement in signaling/SDP, only intended relay paths. If a direct chat remains connected, **fail** this case even when media is relay-only. Currently blocked by missing relayed 1:1 transport. |
| P0 / G2 relay failure | Kill TURN and signaling relay before start, during setup and mid-call; repeat with expired credentials | Private mode fails closed and releases mic/camera; no direct ICE or libp2p fallback. Reconnect requires an authenticated, renewed route. |
| P0 / G3 Wi-Fi ↔ mobile | During a live call switch each phone Wi-Fi→cellular→Wi-Fi, triggering reconnect/ICE restart; repeat when relay is unreachable | Calls recover through relay or end cleanly. Packet capture has no peer-direct packet, host/srflx candidate, or persistent capture after failure. |
| P0 / G4 identity binding | Inject stale/replayed invitations and sender/call-ID substitution across two peers | No ringing or cross-call state mutation; rejected frames do not expose identifiers or SDP in logs. Host tests cover state logic; physical path and logs remain unverified. |
| P0 / G5 API 34+ microphone | On Samsung API 34+, deny then grant RECORD_AUDIO; initiate foreground and background start, hang up during startup | Foreground-service restrictions handled; microphone indicator appears only during active capture and clears after every rejection/teardown. |
| P1 / G6 OEM | Repeat G1–G5 on near-AOSP and Samsung/Xiaomi-class device with normal and battery-restricted background behavior | Same privacy gate; no covert direct fallback, stuck service or unexpected capture. |
| P1 / G7 duration | Voice calls of 5, 30 and 120 minutes; background/foreground repeatedly, measure memory, thermal throttling and battery delta | No growing media queue, sustained capture after hangup or unbounded resource trend; record quantitative thresholds before release. |
| P1 / G8 video | Start only after voice gates pass; exercise camera permission, mute, background, screen lock and network switches | DTLS-SRTP content protected, relay-only path, no camera after teardown; validate actual hardware codec and power behavior. |
| P1 / G9 subscriber and logs | Subscribe to a known contact's deterministic inbox topic, observe relay metadata and collect release logcat | Document timing/size and source-IP visibility accurately; no full call-ID/IdentityId in calling diagnostics. This case is expected to reveal residual metadata, not to pass as anonymity. |

## Minimal first Samsung run

1. Install a build from the reviewed commit on Samsung API 34+ and a second
   phone. Confirm G0 first; the current standard build must not initiate calls.
2. In a controlled opt-in build, keep the current native guard intact. Record
   that startup fails without verified relayed signaling; no microphone or
   camera starts. This is a **successful fail-closed test**, not a call pass.
3. Once relayed signaling and runtime TURN provisioning exist, run G1–G5
   on Samsung and the second phone with sanitized device and relay captures.
   Test denied permission, relay outage, Wi-Fi↔mobile, and teardown first.
4. Only after G1–G5 are green, run G6–G9 and decide whether voice can be a
   release candidate. Video requires its own physical gate. Preserve #79
   open until the matrix is recorded, reviewed and green.

Host-tested: signaling state/replay checks, bounded media queues, payload caps,
and the mono 48 kHz Opus profile. PR #86's relay policy and Coturn staging have
no deployed credential service or two-phone proof. The device procedures above
remain pending; keep #79 open until those results are recorded and reviewed.
