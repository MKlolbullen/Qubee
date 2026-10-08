# Self-hosted calling relay infrastructure: TURN stage

This directory starts **Coturn for media only**. It does not host Qubee's
encrypted 1:1 signaling, issue credentials to Android, or enable calls.
The direct libp2p path remains in the application, so `nativeStartCalling`
continues to fail closed. Never remove that gate merely because Coturn runs.

## Host prerequisites

- Linux VPS with a public IPv4 and Docker Compose. Set a DNS A record such
  as `turn.example.org` to that address. On a NATed host set
  `TURN_EXTERNAL_IP` to its public IPv4 and forward the same ports.
- Valid TLS certificate and private key for the TURN hostname. Keep renewal
  outside this Compose file; reload/restart Coturn after renewal.
- Firewall: inbound 3478/udp, 3478/tcp, 5349/tcp and 49160–49259/udp.
  Start with an allowlist of tester IPs while the system is gated. Do not
  expose the REST shared secret or the generated config file.
- Enough bandwidth and relay ports for expected simultaneous sessions.
  The explicit bounds in `turnserver.conf` are for a small trial, not a
  production capacity estimate.

From this directory:

```sh
cp .env.example .env
# Edit TURN_REALM and, only if needed, TURN_EXTERNAL_IP.
mkdir -m 700 -p secrets
umask 077
openssl rand -hex 32 > secrets/turn-shared-secret
cp /path/to/fullchain.pem secrets/tls.crt
cp /path/to/privkey.pem secrets/tls.key
chmod 600 secrets/*
docker compose config --quiet
docker compose up -d turn
```

The shared secret is read from a Compose secret into a private tmpfs config,
not placed in the APK, Compose environment or command line. The stable
source files under `secrets/` are excluded from git. The tmpfs log may still
contain IP/session data while the container runs; monitor its 16 MiB limit
and protect host-level Docker access. A TLS proxy or generic TCP wrapper
does not hide client IPs from Coturn.

## Issue one credential on a trusted backend

The local issuer is a *server-side primitive*. It has no public endpoint or
user authentication. Run it only after your backend has authenticated and
rate-limited the requesting device, and deliver the JSON over a protected
channel. The helper requires the on-disk secret to be mode 0600.

```sh
python3 issue_turn_credentials.py --secret-file secrets/turn-shared-secret
python3 -m unittest discover -s . -p 'test_*.py'
```

Coturn's TURN REST convention uses `expiry:random` as username and
`base64(HMAC-SHA1(shared_secret, username))` as the password. The random
suffix carries no permanent Qubee identity. The default credential lasts
three hours to cover the planned two-hour voice soak; set a lower TTL only
after the client can renew credentials without dropping an active call.
Rotate the server secret with a planned overlap/migration and test active
allocations; simply replacing it can break ongoing sessions.

Future runtime client configuration should supply both
`turn:turn.example.org:3478?transport=udp` and
`turns:turn.example.org:5349?transport=tcp` with the same short-lived
credentials. Both routes use TURN allocations. Qubee's `RelayOnly` ICE
policy already rejects public STUN and direct ICE candidates.

## Gates before Android calling

1. Add an authenticated and rate-limited credential API. Never serve TURN
   credentials anonymously or ship the shared secret in an app build.
2. Carry the *entire* Qubee 1:1 signaling session over a circuit relay or
   another authenticated encrypted transport. Enforce relay-only dialing
   and address advertisement in the client. A relay server sees client
   IPs, peer routing and timing; its operator must be part of the threat
   model. Regular direct chat can still expose IPs while it is connected.
3. Bind the Android `relay_call_signaling_available` gate to verified
   transport state, not an environment variable or user toggle. Add
   fail-closed reconnect tests and packet capture for zero peer-direct
   packets through Wi-Fi↔mobile and ICE restart.
4. Complete issue #79's two-phone matrix. Debug/host success alone is
   insufficient. Leave the standard calling build gated until these gates
   pass.

Do not deploy Coturn and mark the calling feature private: TURN only changes
the media route, not the current direct signaling route or existing chat
connections.
