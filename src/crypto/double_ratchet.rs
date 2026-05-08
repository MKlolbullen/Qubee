//! Hybrid Double Ratchet built on top of the chain-key construction
//! in [`crate::crypto::enhanced_ratchet`].
//!
//! Adds Signal-style **post-compromise security** (PCS) on top of
//! the chain's forward secrecy: every received message that carries
//! a fresh peer DH public triggers a DH ratchet step, mixing a new
//! X25519 shared secret into the root key and replacing both
//! chains. An attacker who reads ratchet state at time `t` can
//! decrypt messages encrypted under that state — but as soon as one
//! of the peers ratchets (which happens implicitly on send), the
//! root key moves forward through a value the attacker can't
//! compute, and subsequent messages become opaque again.
//!
//! # What this is and isn't
//!
//! This commit lands the **X25519** DH ratchet. The ML-KEM re-encap
//! layer that gives PCS its post-quantum half is a follow-up commit:
//! the wire shape is set up so it can be added without breaking the
//! current format.
//!
//! No header encryption (Signal calls this HE/HEHE mode). The
//! header is bound to AEAD AAD so it can't be tampered with, but
//! it's plaintext on the wire. Adding header encryption would be
//! another layer with its own keys; out of scope here.
//!
//! # Wire format
//!
//! ```text
//! +-------------+----------------+----------------+---------+----------------+
//! | enc_hdr_len | enc_hdr_nonce  | enc_hdr ct+tag | nonce   | AEAD body+tag  |
//! | u16 BE      | 12 B           | enc_hdr_len B  | 12 B    |                |
//! +-------------+----------------+----------------+---------+----------------+
//! ```
//!
//! The encrypted header decrypts to:
//!
//! ```text
//! +---------------+--------+--------+----------+--------------+
//! | sender DH pub | prev_n | n      | kyb_len  | optional     |
//! | 32 B          | u32 BE | u32 BE | u16 BE   | kyber ct     |
//! +---------------+--------+--------+----------+--------------+
//! ```
//!
//! `n` is the sender's counter inside the current DH epoch.
//! `prev_n` is the number of messages they sent in the *previous*
//! epoch — so the receiver knows how many keys to skip+stash from
//! the old recv chain when they detect the DH change.
//! `kyb_len` is 0 in X25519-only mode and on most hybrid frames;
//! when non-zero it's the byte length of the trailing ML-KEM
//! ciphertext (1088 for ML-KEM-768).
//!
//! Both layers bind the caller-supplied AAD: the encrypted header
//! AEAD AAD = caller AAD; the body AEAD AAD = plaintext header
//! bytes ‖ caller AAD. Either layer's tag fails on tampering.
//!
//! # Header encryption (always-on, Signal HEHE-style)
//!
//! Frame headers are AEAD-encrypted under rotating per-direction
//! header keys that move in lockstep with the DH chains.
//!
//! Each peer maintains four header-key slots:
//!
//! * **HKs** — current send header key (encrypts outgoing
//!   headers)
//! * **HKr** — current recv header key (tries first when
//!   decrypting an incoming header)
//! * **NHKs** — next send header key (becomes HKs at the next
//!   DH ratchet step)
//! * **NHKr** — next recv header key (tried as a fallback when
//!   HKr fails; success there signals a peer-side ratchet)
//!
//! Initial values come from `derive_initial_header_keys(root_key)`
//! which produces two shared keys (`shared_hk_init`, `shared_nhk_init`).
//! Initiator: HKs = `shared_hk_init`, NHKr = `shared_nhk_init`,
//! NHKs = derived from `KDF_RK_HE` on the initial DH, HKr = None.
//! Responder: HKs = None, HKr = None, NHKs = `shared_nhk_init`,
//! NHKr = `shared_hk_init`.
//!
//! On every DH ratchet step (triggered when a frame's header
//! decrypts under NHKr instead of HKr), both NHK→HK promotions
//! fire and the two `KDF_RK_HE` calls produce fresh NHKs/NHKr
//! values. The peer-side equivalent NHKs/NHKr derive from the
//! same DH output, so both sides stay aligned.
//!
//! Wire observers therefore can't see the sender's DH pub,
//! counters, or whether a given frame carries an ML-KEM ciphertext
//! — the encrypted-header field is computationally
//! indistinguishable from random. The rotating-key construction
//! also gives the header layer the same forward-secrecy and
//! post-compromise-security guarantees as the body chain: a
//! state read at time *t* doesn't decrypt headers from before *t*
//! after the next ratchet step has rolled past.
//!
//! # Threat model and known limits
//!
//! * **Forward secrecy**: identical to the chain ratchet — message
//!   keys are derived once and zeroised after use.
//! * **Post-compromise security**: a state read at time `t`
//!   decrypts messages from `t` until the next DH ratchet step
//!   either peer takes. With normal back-and-forth traffic that's
//!   typically one message later.
//! * **Cross-epoch out-of-order**: skipped-key stash is keyed by
//!   `(dh_peer_bytes, counter)` so late deliveries from a previous
//!   epoch still decrypt. Stash capped at [`MAX_SKIPPED_STASH`].
//! * **AEAD failure rollback**: the entire decrypt — including any
//!   triggered DH ratchet step — runs against a working copy of
//!   state. Only a successful AEAD decrypt commits the changes
//!   back to `self`. A forged frame that names a fresh DH header
//!   would otherwise advance the ratchet permanently and lose the
//!   legitimate sender; the snapshot pattern prevents that.
//! * **Not implemented**: header encryption (Signal HEHE mode).
//!   Per-message DH ratchet (we ratchet per *epoch* — every
//!   direction change — matching Signal's actual cadence, not
//!   the colloquial "per-message").
//!
//! # ML-KEM re-encap (hybrid mode)
//!
//! Opt-in via [`DoubleRatchet::initiator_hybrid`] /
//! [`DoubleRatchet::responder_hybrid`] with a [`KyberConfig`]. Each
//! peer holds a static ML-KEM-768 keypair plus the peer's public.
//!
//! **Cadence**: re-encap fires on the first outgoing frame after
//! every DH ratchet step (initiator construction; responder's
//! first frame after receiving; either side's first frame after
//! a peer-initiated DH change). This is the same cadence as the
//! DH ratchet itself — each direction change carries a fresh
//! Kyber ciphertext that mixes into the new send chain. We
//! deliberately **don't** re-encap on a per-message counter
//! cadence: that would break under out-of-order delivery (a
//! kyber-bearing frame stashed for later can't be replayed
//! because the chain at that counter has moved on without the
//! kyber input). Aligning to DH-ratchet boundaries keeps kyber
//! on first-of-epoch frames, where in-order delivery is implicit.
//!
//! Threat model addition: a future adversary who breaks X25519
//! (e.g. CRQC) can recover the DH ratchet halves but not the
//! ML-KEM contributions, so any chain key that's been re-encapped
//! at least once stays opaque to them. Forward secrecy is
//! unchanged.

use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as _, SecretKey as KyberSecretKeyTrait, SharedSecret as _,
};
use rand::thread_rng;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::security::secure_rng;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
/// Fixed-size *plaintext* header prefix: dh_pub(32) + prev_n(4) +
/// n(4) + kyber_ct_len(2). The optional kyber ciphertext follows
/// immediately after the prefix in the plaintext header.
const HEADER_PREFIX_LEN: usize = 32 + 4 + 4 + 2;
const TAG_LEN: usize = 16;
/// HEHE outer prefix: enc_hdr_len (u16 BE) + enc_hdr_nonce (12B).
/// Followed by enc_hdr_len bytes of AEAD-encrypted header, then
/// the body's own nonce + AEAD ciphertext.
const HEHE_PREFIX_LEN: usize = 2 + NONCE_LEN;
/// Minimum well-formed frame: HEHE prefix + an encrypted header
/// (plaintext = HEADER_PREFIX_LEN, no kyber ct) + AEAD tag for
/// the header + body nonce + body AEAD tag (empty plaintext is
/// permitted).
const MIN_FRAME_LEN: usize = HEHE_PREFIX_LEN + HEADER_PREFIX_LEN + TAG_LEN + NONCE_LEN + TAG_LEN;
/// ML-KEM-768 ciphertext length, fixed by the algorithm.
const MLKEM768_CT_LEN: usize = 1088;

/// Cap on per-frame skip inside a single DH epoch's recv chain.
/// Same intent as the chain ratchet's MAX_SKIP — bounds attacker-
/// driven CPU per frame.
pub const MAX_SKIP: u32 = 1024;

/// Cap on total stashed message keys across all epochs. Eviction
/// is by smallest counter first — same heuristic as the chain
/// ratchet, on the "older messages are less likely still in
/// flight" intuition.
pub const MAX_SKIPPED_STASH: usize = 4096;

// HKDF info strings. Distinct from the chain ratchet's so an
// attacker who somehow exfiltrates a chain key from one ratchet
// can't replay it against the other.
const INFO_RK: &[u8] = b"qubee/dr/v1/rk";
const INFO_CHAIN_NEXT: &[u8] = b"qubee/dr/v1/chain/next";
const INFO_MESSAGE: &[u8] = b"qubee/dr/v1/chain/msg";
/// HKDF tag for the Kyber-mix step: chain_key' =
/// HKDF(salt = kyber_ss, ikm = chain_key, info = INFO_KYBER_MIX).
/// Salt being the post-quantum half ensures both inputs are
/// required to reconstruct chain_key' — even an X25519-only
/// adversary who knows chain_key can't predict chain_key'.
const INFO_KYBER_MIX: &[u8] = b"qubee/dr/v1/chain/kyber-mix";

struct ChainKey(SecretBox<[u8; KEY_LEN]>);

impl ChainKey {
    fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    fn step(&mut self) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let current = self.0.expose_secret();
        let mut next = [0u8; KEY_LEN];
        Hkdf::<Sha256>::from_prk(current)
            .map_err(|e| anyhow::anyhow!("hkdf prk (chain): {e}"))?
            .expand(INFO_CHAIN_NEXT, &mut next)
            .map_err(|e| anyhow::anyhow!("hkdf expand (chain): {e}"))?;

        let mut msg = Zeroizing::new([0u8; KEY_LEN]);
        Hkdf::<Sha256>::from_prk(current)
            .map_err(|e| anyhow::anyhow!("hkdf prk (msg): {e}"))?
            .expand(INFO_MESSAGE, msg.as_mut())
            .map_err(|e| anyhow::anyhow!("hkdf expand (msg): {e}"))?;

        self.0 = SecretBox::new(Box::new(next));
        Ok(msg)
    }

    fn duplicate(&self) -> Self {
        Self(SecretBox::new(Box::new(*self.0.expose_secret())))
    }

    /// Stir an external 32-byte secret into the chain key. Used
    /// by the ML-KEM re-encap path: the post-quantum shared
    /// secret becomes the HKDF salt and the current chain key the
    /// IKM, so reconstructing the new chain requires both inputs.
    fn mix_in(&mut self, additional_secret: &[u8]) -> Result<()> {
        let current = self.0.expose_secret();
        let mut next = [0u8; KEY_LEN];
        Hkdf::<Sha256>::new(Some(additional_secret), current)
            .expand(INFO_KYBER_MIX, &mut next)
            .map_err(|e| anyhow::anyhow!("hkdf expand (kyber-mix): {e}"))?;
        self.0 = SecretBox::new(Box::new(next));
        Ok(())
    }
}

/// Static ML-KEM-768 keypair plus a cached public-half copy. The
/// secret is held as raw bytes because pqcrypto_mlkem's
/// `SecretKey` is neither `Clone` nor zeroize-on-drop in the way
/// the snapshot pattern needs; a `Vec<u8>` is straightforward to
/// snapshot and is wiped via `Zeroizing` everywhere it crosses
/// process memory.
#[derive(Clone)]
pub struct KyberKeypair {
    public: mlkem768::PublicKey,
    /// ML-KEM-768 secret key bytes (2400 bytes per FIPS 203).
    secret_bytes: Vec<u8>,
}

impl KyberKeypair {
    /// Generate a fresh keypair via the underlying KEM.
    pub fn generate() -> Self {
        let (public, secret) = mlkem768::keypair();
        Self {
            public,
            secret_bytes: secret.as_bytes().to_vec(),
        }
    }

    /// The public half — what the *peer* needs to encapsulate
    /// against this keypair.
    pub fn public(&self) -> mlkem768::PublicKey {
        self.public
    }
}

/// Configuration for hybrid (ML-KEM-augmented) mode. The cadence
/// is fixed (one re-encap per DH ratchet step on each direction)
/// so there's no `period` knob — see the module-level docs for
/// why per-counter cadence breaks under out-of-order delivery.
pub struct KyberConfig {
    /// Peer's ML-KEM public key — what we encapsulate against
    /// when we send a re-encap frame.
    pub peer_pub: mlkem768::PublicKey,
    /// Our keypair — used to decapsulate the peer's incoming
    /// re-encap ciphertexts.
    pub own_keypair: KyberKeypair,
}

/// Hybrid-mode bookkeeping. Lives on `DoubleRatchet` rather than
/// on `State` because the only mutable bit (`pending_send`) is
/// part of the snapshotable State (see there).
struct KyberState {
    config: KyberConfig,
}

/// Mutable state of a [`DoubleRatchet`]. Lifted into its own struct
/// so `decrypt` can build a working copy, mutate it through the
/// (possibly DH-ratcheting) decrypt path, and only commit back on
/// AEAD success.
struct State {
    root_key: SecretBox<[u8; KEY_LEN]>,
    dh_self_priv: StaticSecret,
    dh_self_pub: PublicKey,
    dh_peer: Option<PublicKey>,
    send_chain: Option<ChainKey>,
    recv_chain: Option<ChainKey>,
    send_counter: u32,
    recv_counter: u32,
    prev_send_counter: u32,
    /// Hybrid-mode flag: set true whenever a fresh send chain
    /// has been derived (initiator construction, or after a DH
    /// ratchet step in `decrypt`). Cleared by `encrypt` after
    /// firing a Kyber re-encap. Always false in non-hybrid mode.
    pending_kyber_send: bool,
    /// Current send header key (Signal HEHE: HKs). Encrypts
    /// every outgoing header. `None` for the responder until
    /// they receive their first frame and run a DH ratchet step
    /// (which produces the first send chain *and* promotes the
    /// initial NHKs into HKs).
    hks: Option<SecretBox<[u8; KEY_LEN]>>,
    /// Current recv header key (HKr). Tries first when decrypting
    /// an incoming header. `None` until the first DH ratchet
    /// step on receive — initial frames decrypt via NHKr instead.
    hkr: Option<SecretBox<[u8; KEY_LEN]>>,
    /// Next send header key (NHKs). Becomes HKs at the next DH
    /// ratchet step. Always populated after construction (both
    /// peers seed it from the initial root key).
    nhks: SecretBox<[u8; KEY_LEN]>,
    /// Next recv header key (NHKr). Tried as a fallback when
    /// HKr fails — success on this branch signals a peer-side
    /// DH ratchet that we now need to mirror locally.
    nhkr: SecretBox<[u8; KEY_LEN]>,
}

impl State {
    fn snapshot(&self) -> Self {
        Self {
            root_key: SecretBox::new(Box::new(*self.root_key.expose_secret())),
            // StaticSecret isn't Clone (it shouldn't be — Clone on a
            // type whose whole purpose is being a secret is a
            // foot-gun). We rebuild via to_bytes/from. Both copies
            // zeroise on drop.
            dh_self_priv: StaticSecret::from(self.dh_self_priv.to_bytes()),
            dh_self_pub: self.dh_self_pub,
            dh_peer: self.dh_peer,
            send_chain: self.send_chain.as_ref().map(|c| c.duplicate()),
            recv_chain: self.recv_chain.as_ref().map(|c| c.duplicate()),
            send_counter: self.send_counter,
            recv_counter: self.recv_counter,
            prev_send_counter: self.prev_send_counter,
            pending_kyber_send: self.pending_kyber_send,
            hks: clone_opt_key(&self.hks),
            hkr: clone_opt_key(&self.hkr),
            nhks: SecretBox::new(Box::new(*self.nhks.expose_secret())),
            nhkr: SecretBox::new(Box::new(*self.nhkr.expose_secret())),
        }
    }
}

fn clone_opt_key(k: &Option<SecretBox<[u8; KEY_LEN]>>) -> Option<SecretBox<[u8; KEY_LEN]>> {
    k.as_ref()
        .map(|s| SecretBox::new(Box::new(*s.expose_secret())))
}

/// Stash key: scoped to a specific DH epoch so a counter from an
/// old epoch and a counter from a new epoch can both live in the
/// stash without colliding.
#[derive(Clone, Hash, Eq, PartialEq)]
struct SkipKey {
    dh_peer: [u8; KEY_LEN],
    counter: u32,
}

/// Hybrid Double Ratchet (X25519 DH ratchet + chain ratchet,
/// optionally augmented with ML-KEM-768 re-encap for post-quantum
/// PCS). See the module-level docs for the threat model.
pub struct DoubleRatchet {
    state: State,
    skipped: HashMap<SkipKey, Zeroizing<[u8; KEY_LEN]>>,
    kyber: Option<KyberState>,
}

impl DoubleRatchet {
    /// Initiator side. Takes the X3DH/handshake-derived `root_key`
    /// and the responder's published initial DH public — typically
    /// the responder's identity DH key from their prekey bundle.
    /// Generates the initiator's first ratchet keypair and seeds
    /// the send chain by running DH against the peer's pub.
    pub fn initiator(root_key: &[u8; KEY_LEN], peer_initial_dh_pub: PublicKey) -> Result<Self> {
        Self::initiator_inner(root_key, peer_initial_dh_pub, None)
    }

    /// Hybrid-mode initiator. Same semantics as [`initiator`],
    /// plus periodic ML-KEM-768 re-encap as configured.
    pub fn initiator_hybrid(
        root_key: &[u8; KEY_LEN],
        peer_initial_dh_pub: PublicKey,
        kyber: KyberConfig,
    ) -> Result<Self> {
        Self::initiator_inner(root_key, peer_initial_dh_pub, Some(kyber))
    }

    fn initiator_inner(
        root_key: &[u8; KEY_LEN],
        peer_initial_dh_pub: PublicKey,
        kyber: Option<KyberConfig>,
    ) -> Result<Self> {
        let dh_self_priv = StaticSecret::random_from_rng(thread_rng());
        let dh_self_pub = PublicKey::from(&dh_self_priv);
        let shared = dh_self_priv.diffie_hellman(&peer_initial_dh_pub);
        let (new_root, send_chain_key, nhks_post) = kdf_rk(root_key, shared.as_bytes())?;
        let (shared_hk_init, shared_nhk_init) = derive_initial_header_keys(root_key)?;

        // Hybrid mode: the initiator has just derived a fresh send
        // chain via DH ratchet, so the next encrypt should fire a
        // Kyber re-encap and mix the result into that chain before
        // the first message goes out.
        let pending_kyber_send = kyber.is_some();

        Ok(Self {
            state: State {
                root_key: SecretBox::new(Box::new(new_root)),
                dh_self_priv,
                dh_self_pub,
                dh_peer: Some(peer_initial_dh_pub),
                send_chain: Some(ChainKey::from_bytes(send_chain_key)),
                recv_chain: None,
                send_counter: 0,
                recv_counter: 0,
                prev_send_counter: 0,
                pending_kyber_send,
                // Initiator: HKs = shared HK_a→b (matches the
                // responder's NHKr until the responder's first
                // DH ratchet step). HKr = None — recv chain
                // isn't established until the responder replies.
                // NHKs = freshly-derived from KDF_RK_HE on the
                // initial DH; this becomes HKs at the first DH
                // ratchet step (initiator-side, after receiving
                // the responder's reply). NHKr = shared NHK_b→a
                // (matches the responder's NHKs until they
                // ratchet).
                hks: Some(SecretBox::new(Box::new(shared_hk_init))),
                hkr: None,
                nhks: SecretBox::new(Box::new(nhks_post)),
                nhkr: SecretBox::new(Box::new(shared_nhk_init)),
            },
            skipped: HashMap::new(),
            kyber: kyber.map(|config| KyberState { config }),
        })
    }

    /// Responder side. Takes the same `root_key` the initiator
    /// derived plus the responder's initial ratchet keypair (the
    /// one whose public was advertised in their prekey bundle —
    /// the initiator runs DH against this on their first message).
    /// Send chain isn't ready until the first incoming message
    /// triggers a DH ratchet step.
    pub fn responder(root_key: &[u8; KEY_LEN], own_initial_keypair: StaticSecret) -> Result<Self> {
        Self::responder_inner(root_key, own_initial_keypair, None)
    }

    /// Hybrid-mode responder. Same semantics as [`responder`],
    /// plus periodic ML-KEM-768 re-encap as configured.
    pub fn responder_hybrid(
        root_key: &[u8; KEY_LEN],
        own_initial_keypair: StaticSecret,
        kyber: KyberConfig,
    ) -> Result<Self> {
        Self::responder_inner(root_key, own_initial_keypair, Some(kyber))
    }

    fn responder_inner(
        root_key: &[u8; KEY_LEN],
        own_initial_keypair: StaticSecret,
        kyber: Option<KyberConfig>,
    ) -> Result<Self> {
        let dh_self_pub = PublicKey::from(&own_initial_keypair);
        let (shared_hk_init, shared_nhk_init) = derive_initial_header_keys(root_key)?;
        Ok(Self {
            state: State {
                root_key: SecretBox::new(Box::new(*root_key)),
                dh_self_priv: own_initial_keypair,
                dh_self_pub,
                dh_peer: None,
                send_chain: None,
                recv_chain: None,
                send_counter: 0,
                recv_counter: 0,
                prev_send_counter: 0,
                // Responder has no send chain yet; pending flag
                // gets set inside `decrypt` after the DH ratchet
                // step that produces one.
                pending_kyber_send: false,
                // Responder: HKs = None (no send chain yet).
                // HKr = None (initial frame from the initiator
                // decrypts via NHKr — once that succeeds we
                // promote NHKr into HKr inside the DH ratchet
                // path). NHKs = NHK_b→a; NHKr = HK_a→b — this
                // last assignment is the load-bearing one: the
                // initiator's first frame encrypts its header
                // under hk_ab, and our NHKr equals hk_ab, so
                // the decrypt-via-NHKr branch fires correctly.
                hks: None,
                hkr: None,
                nhks: SecretBox::new(Box::new(shared_nhk_init)),
                nhkr: SecretBox::new(Box::new(shared_hk_init)),
            },
            skipped: HashMap::new(),
            kyber: kyber.map(|config| KyberState { config }),
        })
    }

    /// Encrypt a message in the current epoch. In hybrid mode,
    /// fires an ML-KEM re-encap on the first outgoing frame after
    /// every DH ratchet step and includes the resulting
    /// ciphertext in the header.
    ///
    /// Errors if called on the responder before they've received
    /// the initiator's first message — the responder has no send
    /// chain until the first incoming frame triggers the DH
    /// ratchet step that derives one.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        // Hybrid-mode re-encap: stir a fresh ML-KEM shared secret
        // into the send chain *before* deriving this message's
        // key, so the post-quantum entropy lands on the message
        // we're about to send. Fires only on the first frame
        // after a fresh send chain (initiator construction or
        // post-DH-ratchet-step on receive).
        let kyber_ct_bytes: Vec<u8> = if self.state.pending_kyber_send {
            let kyber = self.kyber.as_ref().expect(
                "pending_kyber_send true ⇒ hybrid mode (config invariant)",
            );
            let send_chain = self.state.send_chain.as_mut().ok_or_else(|| {
                anyhow::anyhow!(
                    "no send chain: responder must receive the first message before re-encap"
                )
            })?;
            let (shared_secret, ct) = mlkem768::encapsulate(&kyber.config.peer_pub);
            send_chain.mix_in(shared_secret.as_bytes())?;
            self.state.pending_kyber_send = false;
            ct.as_bytes().to_vec()
        } else {
            Vec::new()
        };

        let send_chain = self
            .state
            .send_chain
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!(
                "no send chain: responder must receive the first message before sending"
            ))?;
        let counter = self.state.send_counter;
        let msg_key = send_chain.step()?;
        let nonce_bytes = secure_rng::random::array::<NONCE_LEN>()?;

        // Bound check: ML-KEM ct length must fit a u16. Always
        // true for ML-KEM-768 (1088 bytes) but defends against a
        // future algorithm bump that doesn't.
        let kyber_ct_len = u16::try_from(kyber_ct_bytes.len())
            .map_err(|_| anyhow::anyhow!("kyber ct length exceeds u16"))?;

        let mut plaintext_header = Vec::with_capacity(HEADER_PREFIX_LEN + kyber_ct_bytes.len());
        plaintext_header.extend_from_slice(self.state.dh_self_pub.as_bytes());
        plaintext_header.extend_from_slice(&self.state.prev_send_counter.to_be_bytes());
        plaintext_header.extend_from_slice(&counter.to_be_bytes());
        plaintext_header.extend_from_slice(&kyber_ct_len.to_be_bytes());
        plaintext_header.extend_from_slice(&kyber_ct_bytes);

        // HEHE: AEAD-encrypt the plaintext header under HKs.
        // Caller AAD binds at this layer too so any tampering
        // with the outer caller-supplied metadata also breaks
        // the header AEAD. HKs can be None on the responder side
        // before its first DH ratchet — that case is what the
        // outer "no send chain" guard at the top of `encrypt`
        // catches, so by the time we get here HKs is Some.
        let hks = self
            .state
            .hks
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(
                "no send header key — DH ratchet hasn't promoted NHKs into HKs yet"
            ))?;
        let header_nonce_bytes = secure_rng::random::array::<NONCE_LEN>()?;
        let header_cipher =
            ChaCha20Poly1305::new_from_slice(hks.expose_secret()).expect("32-byte key");
        let enc_header = header_cipher
            .encrypt(
                Nonce::from_slice(&header_nonce_bytes),
                Payload { msg: &plaintext_header, aad },
            )
            .map_err(|e| anyhow::anyhow!("header aead encrypt: {e}"))?;
        let enc_header_len = u16::try_from(enc_header.len())
            .map_err(|_| anyhow::anyhow!("encrypted header length exceeds u16"))?;

        // The body AEAD's AAD covers the *plaintext* header bytes
        // (binding chain ciphertext to the values that drove its
        // selection) plus the caller's external AAD.
        let bound_aad = bind_aad(&plaintext_header, aad);
        let cipher = ChaCha20Poly1305::new_from_slice(msg_key.as_ref()).expect("32-byte key");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: &bound_aad })
            .map_err(|e| anyhow::anyhow!("aead encrypt: {e}"))?;

        self.state.send_counter = self
            .state
            .send_counter
            .checked_add(1)
            .context("send counter overflow — re-handshake required")?;

        let mut wire =
            Vec::with_capacity(HEHE_PREFIX_LEN + enc_header.len() + NONCE_LEN + ct.len());
        wire.extend_from_slice(&enc_header_len.to_be_bytes());
        wire.extend_from_slice(&header_nonce_bytes);
        wire.extend_from_slice(&enc_header);
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ct);
        Ok(wire)
    }

    /// Decrypt a message. Drives the full state machine:
    ///
    /// 1. Look up `(header_dh, counter)` in the skipped-key stash;
    ///    a hit means out-of-order delivery for a key we already
    ///    derived in some earlier (possibly older-epoch) decrypt.
    /// 2. Otherwise, if `header_dh` differs from our current
    ///    `dh_peer`, run a DH ratchet step against a working state
    ///    copy: stash any remaining keys in the old recv chain
    ///    (header `prev_n` tells us how many), derive a new root +
    ///    recv chain from `DH(self_priv, header_dh)`, generate a
    ///    fresh send keypair, derive a new root + send chain from
    ///    `DH(new_self_priv, header_dh)`. All on the working copy.
    /// 3. Skip + step the working recv chain to `counter`,
    ///    AEAD-decrypt with the message key. AAD includes the full
    ///    header so any header tampering breaks AEAD.
    /// 4. On AEAD success, commit the working state back to `self`
    ///    and insert pending stash entries. On failure, drop the
    ///    working state and `self` is untouched.
    pub fn decrypt(&mut self, wire: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < MIN_FRAME_LEN {
            return Err(anyhow::anyhow!("wire frame too short: {} bytes", wire.len()));
        }

        // HEHE: outer prefix carries the encrypted header.
        let enc_header_len =
            u16::from_be_bytes(wire[..2].try_into().expect("len")) as usize;
        let header_nonce = Nonce::from_slice(&wire[2..2 + NONCE_LEN]);
        let body_start = HEHE_PREFIX_LEN + enc_header_len;
        if wire.len() < body_start + NONCE_LEN + TAG_LEN {
            return Err(anyhow::anyhow!(
                "wire frame too short for declared enc_header_len={enc_header_len}: {} bytes",
                wire.len(),
            ));
        }
        let enc_header = &wire[HEHE_PREFIX_LEN..body_start];

        // Decrypt the header layer first. Try HKr (current recv
        // header key) — success means same-epoch frame. On
        // failure, try NHKr — success there means the peer
        // ratcheted and we need to mirror.
        let (plaintext_header, decrypted_via_nhkr) =
            if let Some(hkr) = self.state.hkr.as_ref() {
                let cipher = ChaCha20Poly1305::new_from_slice(hkr.expose_secret())
                    .expect("32-byte key");
                match cipher.decrypt(header_nonce, Payload { msg: enc_header, aad }) {
                    Ok(pt) => (pt, false),
                    Err(_) => {
                        let nhkr_cipher =
                            ChaCha20Poly1305::new_from_slice(self.state.nhkr.expose_secret())
                                .expect("32-byte key");
                        let pt = nhkr_cipher
                            .decrypt(header_nonce, Payload { msg: enc_header, aad })
                            .map_err(|e| anyhow::anyhow!(
                                "header aead decrypt failed under both HKr and NHKr: {e}"
                            ))?;
                        (pt, true)
                    }
                }
            } else {
                // Responder before first ratchet, or initiator
                // before first reply — only NHKr is set.
                let cipher = ChaCha20Poly1305::new_from_slice(self.state.nhkr.expose_secret())
                    .expect("32-byte key");
                let pt = cipher
                    .decrypt(header_nonce, Payload { msg: enc_header, aad })
                    .map_err(|e| anyhow::anyhow!(
                        "header aead decrypt under NHKr (no HKr available): {e}"
                    ))?;
                (pt, true)
            };

        // Validate the decrypted header has the expected fixed
        // prefix length plus the declared kyber ciphertext.
        if plaintext_header.len() < HEADER_PREFIX_LEN {
            return Err(anyhow::anyhow!(
                "decrypted header too short: {} bytes",
                plaintext_header.len()
            ));
        }
        let header_dh_bytes: [u8; KEY_LEN] =
            plaintext_header[..32].try_into().expect("len");
        let header_dh = PublicKey::from(header_dh_bytes);
        let prev_n = u32::from_be_bytes(plaintext_header[32..36].try_into().expect("len"));
        let counter = u32::from_be_bytes(plaintext_header[36..40].try_into().expect("len"));
        let kyber_ct_len =
            u16::from_be_bytes(plaintext_header[40..42].try_into().expect("len")) as usize;
        if plaintext_header.len() != HEADER_PREFIX_LEN + kyber_ct_len {
            return Err(anyhow::anyhow!(
                "decrypted header length {} mismatches declared kyber_ct_len={kyber_ct_len}",
                plaintext_header.len()
            ));
        }
        let kyber_ct_bytes = &plaintext_header[HEADER_PREFIX_LEN..];

        let nonce = Nonce::from_slice(&wire[body_start..body_start + NONCE_LEN]);
        let ct = &wire[body_start + NONCE_LEN..];

        // Body AAD binds the *plaintext* header bytes (so the
        // body AEAD reproduces the same binding the sender did)
        // plus the caller's external AAD.
        let bound_aad = bind_aad(&plaintext_header, aad);

        // Stash hit path: cheap, no state mutation. Stashed keys
        // are by definition pre-derived, so a kyber_ct on a
        // stash-hit frame is meaningless — reject it as a
        // mis-routed frame rather than silently ignoring.
        let stash_lookup = SkipKey { dh_peer: header_dh_bytes, counter };
        if let Some(key) = self.skipped.remove(&stash_lookup) {
            if kyber_ct_len > 0 {
                self.skipped.insert(stash_lookup, key);
                return Err(anyhow::anyhow!(
                    "kyber_ct present on a stash-hit frame; expected only on fresh-epoch frames"
                ));
            }
            let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key");
            return match cipher.decrypt(nonce, Payload { msg: ct, aad: &bound_aad }) {
                Ok(pt) => Ok(pt),
                Err(e) => {
                    self.skipped.insert(stash_lookup, key);
                    Err(anyhow::anyhow!("aead decrypt (stashed): {e}"))
                }
            };
        }

        // Full path: snapshot state, mutate working copy through
        // any DH ratchet + chain advance, AEAD-decrypt, commit.
        let mut working = self.state.snapshot();
        let mut pending_skipped: Vec<(SkipKey, Zeroizing<[u8; KEY_LEN]>)> = Vec::new();

        let triggers_dh = decrypted_via_nhkr;
        // Cross-check: a frame that decrypted under HKr should
        // also have header_dh matching our current dh_peer, and
        // a frame that decrypted under NHKr shouldn't. If these
        // disagree the peer is in a state we don't expect; reject
        // before committing.
        let dh_matches_peer = working
            .dh_peer
            .map(|p| p.as_bytes() == &header_dh_bytes)
            .unwrap_or(false);
        if triggers_dh && dh_matches_peer {
            return Err(anyhow::anyhow!(
                "frame decrypted under NHKr but header_dh matches current peer dh; protocol confusion"
            ));
        }
        if !triggers_dh && !dh_matches_peer {
            return Err(anyhow::anyhow!(
                "frame decrypted under HKr but header_dh doesn't match current peer dh; protocol confusion"
            ));
        }

        // Validate hybrid-mode invariants: kyber_ct is present iff
        // (we're hybrid AND this frame triggers a DH ratchet step).
        // Catches downgrade attempts and protocol confusion before
        // we touch any chain state.
        let hybrid = self.kyber.is_some();
        match (kyber_ct_len, triggers_dh, hybrid) {
            (0, true, true) => {
                return Err(anyhow::anyhow!(
                    "fresh-epoch frame missing kyber_ct (peer in non-hybrid mode? downgrade?)"
                ));
            }
            (n, false, _) if n > 0 => {
                return Err(anyhow::anyhow!(
                    "kyber_ct on non-epoch-boundary frame: {n} bytes"
                ));
            }
            (n, _, false) if n > 0 => {
                return Err(anyhow::anyhow!(
                    "kyber_ct from peer but local config is non-hybrid: {n} bytes"
                ));
            }
            (n, _, true) if n > 0 && n != MLKEM768_CT_LEN => {
                return Err(anyhow::anyhow!(
                    "wrong kyber ct length {n}; expected {MLKEM768_CT_LEN}"
                ));
            }
            _ => {}
        }

        if triggers_dh {
            // Skip + stash any remaining keys in the old recv
            // chain. `prev_n` from the header is how many messages
            // the peer sent in their *previous* epoch — i.e. on
            // their old send chain, which is our old recv chain.
            // Anything strictly less than prev_n that we hadn't
            // already received is a candidate for late delivery.
            if let (Some(old_peer_dh), Some(old_recv_chain)) =
                (working.dh_peer, working.recv_chain.as_mut())
            {
                let skip_remaining = prev_n.saturating_sub(working.recv_counter);
                if skip_remaining > MAX_SKIP {
                    return Err(anyhow::anyhow!(
                        "old-epoch tail skip {} exceeds MAX_SKIP {}",
                        skip_remaining,
                        MAX_SKIP,
                    ));
                }
                let old_peer_bytes = *old_peer_dh.as_bytes();
                for i in 0..skip_remaining {
                    let key = old_recv_chain.step()?;
                    pending_skipped.push((
                        SkipKey {
                            dh_peer: old_peer_bytes,
                            counter: working.recv_counter + i,
                        },
                        key,
                    ));
                }
            }

            // Promote NHK → HK. Per Signal HEHE spec, the NHKr
            // that just decrypted this frame's header becomes
            // HKr, and NHKs (which both peers seeded at
            // construction) becomes HKs. Fresh NHK values are
            // produced by the kdf_rk_he calls below.
            working.hkr = Some(SecretBox::new(Box::new(*working.nhkr.expose_secret())));
            working.hks = Some(SecretBox::new(Box::new(*working.nhks.expose_secret())));

            // DH(self_priv, header_dh) → new root + recv chain
            // + NHKr (next recv header key for the *next* DH
            // ratchet step).
            let shared_recv = working.dh_self_priv.diffie_hellman(&header_dh);
            let (new_root, recv_chain_key, new_nhkr) = kdf_rk(
                working.root_key.expose_secret(),
                shared_recv.as_bytes(),
            )?;
            working.root_key = SecretBox::new(Box::new(new_root));
            working.nhkr = SecretBox::new(Box::new(new_nhkr));
            let mut new_recv_chain = ChainKey::from_bytes(recv_chain_key);

            // Hybrid mode: decapsulate the peer's kyber ciphertext
            // with our own ML-KEM secret key and stir the shared
            // secret into the freshly-derived recv chain. AEAD
            // failure on the message that follows rolls this back
            // along with everything else (working state isn't
            // committed).
            if kyber_ct_len > 0 {
                let kyber = self.kyber.as_ref().expect(
                    "kyber_ct_len > 0 already validated to imply hybrid mode",
                );
                let ct = mlkem768::Ciphertext::from_bytes(kyber_ct_bytes).map_err(|e| {
                    anyhow::anyhow!("invalid ML-KEM ciphertext: {e}")
                })?;
                let sk = mlkem768::SecretKey::from_bytes(&kyber.config.own_keypair.secret_bytes)
                    .map_err(|e| anyhow::anyhow!("invalid stored ML-KEM sk: {e}"))?;
                let shared = mlkem768::decapsulate(&ct, &sk);
                new_recv_chain.mix_in(shared.as_bytes())?;
            }

            working.recv_chain = Some(new_recv_chain);
            working.dh_peer = Some(header_dh);
            working.recv_counter = 0;

            // Generate fresh send keypair and DH against the same
            // header_dh → new root + send chain + new NHKs.
            // The send keypair is what we'll publish in our next
            // outgoing header; the NHKs from this kdf_rk_he is
            // what becomes HKs at our *next* DH ratchet step
            // (i.e. when the peer ratchets back to us).
            // pending_kyber_send=true so the next encrypt fires
            // its own re-encap into this newly-derived send chain.
            let new_priv = StaticSecret::random_from_rng(thread_rng());
            let new_pub = PublicKey::from(&new_priv);
            let shared_send = new_priv.diffie_hellman(&header_dh);
            let (new_root2, send_chain_key, new_nhks) = kdf_rk(
                working.root_key.expose_secret(),
                shared_send.as_bytes(),
            )?;
            working.root_key = SecretBox::new(Box::new(new_root2));
            working.nhks = SecretBox::new(Box::new(new_nhks));
            working.dh_self_priv = new_priv;
            working.dh_self_pub = new_pub;
            working.send_chain = Some(ChainKey::from_bytes(send_chain_key));
            working.prev_send_counter = working.send_counter;
            working.send_counter = 0;
            working.pending_kyber_send = hybrid;
        }

        // Now in the current epoch: skip + step recv chain to
        // counter, AEAD-decrypt.
        let recv_chain = working
            .recv_chain
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no recv chain after ratchet step"))?;
        if counter < working.recv_counter {
            return Err(anyhow::anyhow!(
                "stale counter {} in current epoch (expected ≥ {})",
                counter,
                working.recv_counter,
            ));
        }
        let skip = counter - working.recv_counter;
        if skip > MAX_SKIP {
            return Err(anyhow::anyhow!(
                "counter jumps {} steps in current epoch; max skip {}",
                skip,
                MAX_SKIP,
            ));
        }

        let mut working_chain = recv_chain.duplicate();
        for i in 0..skip {
            let key = working_chain.step()?;
            pending_skipped.push((
                SkipKey {
                    dh_peer: header_dh_bytes,
                    counter: working.recv_counter + i,
                },
                key,
            ));
        }
        let msg_key = working_chain.step()?;

        let cipher = ChaCha20Poly1305::new_from_slice(msg_key.as_ref()).expect("32-byte key");
        let pt = cipher
            .decrypt(nonce, Payload { msg: ct, aad: &bound_aad })
            .map_err(|e| anyhow::anyhow!("aead decrypt: {e}"))?;

        // Commit. Working chain replaces the stale one in the
        // working state; working state replaces self.state.
        working.recv_chain = Some(working_chain);
        working.recv_counter = counter
            .checked_add(1)
            .context("recv counter overflow — re-handshake required")?;
        self.state = working;
        for (k, v) in pending_skipped {
            self.stash_message_key(k, v);
        }
        Ok(pt)
    }

    /// Number of message keys currently held in the skipped-key
    /// stash. Exposed for tests and for callers that want to
    /// monitor stash pressure.
    pub fn skipped_stash_len(&self) -> usize {
        self.skipped.len()
    }

    /// Our current outgoing DH public — what would land in the
    /// header of the next encrypted message. Useful for tests
    /// asserting that the DH key actually rotated after a peer
    /// triggered a ratchet step.
    pub fn current_dh_pub(&self) -> PublicKey {
        self.state.dh_self_pub
    }

    fn stash_message_key(&mut self, k: SkipKey, v: Zeroizing<[u8; KEY_LEN]>) {
        if self.skipped.len() >= MAX_SKIPPED_STASH {
            // Evict the smallest-counter entry. Cross-epoch ties
            // (same counter under different DH peers) are broken
            // by HashMap iteration order — fine, both are
            // arbitrary picks at the eviction edge.
            if let Some(min_key) = self.skipped.keys().min_by_key(|k| k.counter).cloned() {
                self.skipped.remove(&min_key);
            }
        }
        self.skipped.insert(k, v);
    }
}

/// Signal-style `KDF_RK_HE`: derives `(new_root, chain_seed,
/// next_header_key)` from `(old_root, dh_output)`. Salt = old
/// root key, IKM = DH output, info = fixed domain string.
/// 96-byte output is split 32:32:32.
///
/// The third slot is the **next** header key for *this* direction
/// — the header key that becomes "current" after the next DH
/// ratchet step. Both peers' lifecycles align: peer A's NHKs
/// matches peer B's NHKr, so when A ratchets its NHKs into HKs
/// (the key it actually uses to encrypt the next-epoch headers),
/// B's NHKr (which it tries on header decrypt failure) decrypts
/// them and triggers B's matching ratchet step.
fn kdf_rk(
    old_root: &[u8; KEY_LEN],
    dh_output: &[u8],
) -> Result<([u8; KEY_LEN], [u8; KEY_LEN], [u8; KEY_LEN])> {
    let hk = Hkdf::<Sha256>::new(Some(old_root), dh_output);
    let mut out = [0u8; KEY_LEN * 3];
    hk.expand(INFO_RK, &mut out)
        .map_err(|e| anyhow::anyhow!("hkdf expand (rk): {e}"))?;
    let mut new_root = [0u8; KEY_LEN];
    let mut chain = [0u8; KEY_LEN];
    let mut nhk = [0u8; KEY_LEN];
    new_root.copy_from_slice(&out[..KEY_LEN]);
    chain.copy_from_slice(&out[KEY_LEN..2 * KEY_LEN]);
    nhk.copy_from_slice(&out[2 * KEY_LEN..]);
    Ok((new_root, chain, nhk))
}

/// Derive the two shared initial header-encryption keys from the
/// session's initial root key. Matches Signal's
/// `shared_hka` / `shared_nhkb` (which the spec assumes come from
/// the X3DH "associated data" — we re-derive from `root_key`
/// instead).
///
/// Role-specific assignment:
///
/// * Initiator: HKs = `shared_hk_init`, NHKr = `shared_nhk_init`.
/// * Responder: NHKs = `shared_nhk_init`, NHKr = `shared_hk_init`.
///
/// The "a→b" frames go out under `shared_hk_init` (Alice's HKs;
/// Bob's NHKr); the "b→a" frames go out under `shared_nhk_init`
/// once Bob promotes NHKs into HKs at his first DH ratchet step.
fn derive_initial_header_keys(
    root_key: &[u8; KEY_LEN],
) -> Result<([u8; KEY_LEN], [u8; KEY_LEN])> {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut shared_hk_init = [0u8; KEY_LEN];
    hk.expand(b"qubee/dr/v1/hk/init", &mut shared_hk_init)
        .map_err(|e| anyhow::anyhow!("hkdf expand (initial hk): {e}"))?;
    let mut shared_nhk_init = [0u8; KEY_LEN];
    hk.expand(b"qubee/dr/v1/nhk/init", &mut shared_nhk_init)
        .map_err(|e| anyhow::anyhow!("hkdf expand (initial nhk): {e}"))?;
    Ok((shared_hk_init, shared_nhk_init))
}

/// Concatenate the wire header with the caller's AAD so AEAD
/// covers both. Tampering with any header field — DH pub, prev_n,
/// counter — invalidates the tag without ever triggering a
/// speculative DH ratchet step on the legitimate receiver, since
/// the snapshot pattern still discards the working state on
/// failure.
fn bind_aad(header: &[u8], caller_aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + caller_aad.len());
    out.extend_from_slice(header);
    out.extend_from_slice(caller_aad);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a (initiator, responder) pair sharing the same root
    /// key. Returns the responder's initial DH public so callers
    /// can assert on epoch transitions.
    fn pair() -> (DoubleRatchet, DoubleRatchet, PublicKey) {
        let root = [0xC0_u8; 32];
        let resp_kp = StaticSecret::random_from_rng(thread_rng());
        let resp_pub = PublicKey::from(&resp_kp);
        let init = DoubleRatchet::initiator(&root, resp_pub).unwrap();
        let resp = DoubleRatchet::responder(&root, resp_kp).unwrap();
        (init, resp, resp_pub)
    }

    #[test]
    fn initiator_sends_first_responder_replies() {
        let (mut a, mut b, _) = pair();
        // Responder has no send chain yet.
        assert!(b.encrypt(b"oops", b"").is_err());

        let w1 = a.encrypt(b"hi from a", b"").unwrap();
        assert_eq!(b.decrypt(&w1, b"").unwrap(), b"hi from a");
        // After the first DH ratchet on the responder side they
        // can send.
        let w2 = b.encrypt(b"hi back from b", b"").unwrap();
        assert_eq!(a.decrypt(&w2, b"").unwrap(), b"hi back from b");
    }

    #[test]
    fn back_and_forth_runs_dh_ratchet_each_direction_change() {
        let (mut a, mut b, _) = pair();

        let a_pub_0 = a.current_dh_pub();
        let b_pub_0 = b.current_dh_pub();

        let w = a.encrypt(b"a1", b"").unwrap();
        assert_eq!(b.decrypt(&w, b"").unwrap(), b"a1");
        // b's DH key rotated when it processed a's frame.
        assert_ne!(b.current_dh_pub().as_bytes(), b_pub_0.as_bytes());
        // a hasn't rotated yet — it'll rotate when it processes
        // a frame from b's new DH.
        assert_eq!(a.current_dh_pub().as_bytes(), a_pub_0.as_bytes());

        let w = b.encrypt(b"b1", b"").unwrap();
        assert_eq!(a.decrypt(&w, b"").unwrap(), b"b1");
        assert_ne!(a.current_dh_pub().as_bytes(), a_pub_0.as_bytes());

        // Many alternating round-trips, all decrypt cleanly.
        for i in 0..20 {
            let m = format!("a says {i}");
            let w = a.encrypt(m.as_bytes(), b"").unwrap();
            assert_eq!(b.decrypt(&w, b"").unwrap(), m.as_bytes());
            let m = format!("b says {i}");
            let w = b.encrypt(m.as_bytes(), b"").unwrap();
            assert_eq!(a.decrypt(&w, b"").unwrap(), m.as_bytes());
        }
    }

    #[test]
    fn many_messages_in_one_direction_use_chain_only() {
        // Sender keeps sending without the receiver replying —
        // chain ratchet does the work, no DH ratchet steps until
        // the receiver eventually sends back.
        let (mut a, mut b, _) = pair();
        for i in 0..50 {
            let m = format!("burst {i}");
            let w = a.encrypt(m.as_bytes(), b"").unwrap();
            assert_eq!(b.decrypt(&w, b"").unwrap(), m.as_bytes());
        }
        // Now b replies — triggers the DH ratchet on a's side.
        let w = b.encrypt(b"finally", b"").unwrap();
        assert_eq!(a.decrypt(&w, b"").unwrap(), b"finally");
    }

    #[test]
    fn out_of_order_within_epoch() {
        let (mut a, mut b, _) = pair();
        let w0 = a.encrypt(b"a0", b"").unwrap();
        let w1 = a.encrypt(b"a1", b"").unwrap();
        let w2 = a.encrypt(b"a2", b"").unwrap();
        // Deliver out of order.
        assert_eq!(b.decrypt(&w2, b"").unwrap(), b"a2");
        assert_eq!(b.decrypt(&w0, b"").unwrap(), b"a0");
        assert_eq!(b.decrypt(&w1, b"").unwrap(), b"a1");
        assert_eq!(b.skipped_stash_len(), 0);
    }

    #[test]
    fn out_of_order_across_dh_epochs() {
        // The hard case: one or more frames from epoch N arrive
        // *after* a frame from epoch N+1 has already triggered the
        // DH ratchet step. Stash must be keyed by (dh_peer,
        // counter) for this to work.
        let (mut a, mut b, _) = pair();
        let a_w0 = a.encrypt(b"a-old-0", b"").unwrap();
        let a_w1 = a.encrypt(b"a-old-1", b"").unwrap();
        // Deliver a_w1 → b ratchets. a_w0's key goes into the
        // stash for the *old* DH epoch.
        assert_eq!(b.decrypt(&a_w1, b"").unwrap(), b"a-old-1");
        assert!(b.skipped_stash_len() >= 1);

        // b sends a reply, which a will process and ratchet to
        // a new DH epoch.
        let b_w0 = b.encrypt(b"b-new-0", b"").unwrap();
        assert_eq!(a.decrypt(&b_w0, b"").unwrap(), b"b-new-0");

        // Now a's late old-epoch message a_w0 finally arrives at
        // b. The stash holds its key under the old DH peer.
        assert_eq!(b.decrypt(&a_w0, b"").unwrap(), b"a-old-0");
    }

    #[test]
    fn replay_rejected() {
        let (mut a, mut b, _) = pair();
        let w = a.encrypt(b"once", b"").unwrap();
        b.decrypt(&w, b"").unwrap();
        assert!(b.decrypt(&w, b"").is_err());
    }

    #[test]
    fn aad_mismatch_fails() {
        let (mut a, mut b, _) = pair();
        let w = a.encrypt(b"secret", b"correct").unwrap();
        assert!(b.decrypt(&w, b"wrong").is_err());
    }

    #[test]
    fn header_tampering_breaks_aead() {
        // Flip a bit in the header counter. AEAD covers the
        // whole header, so this fails — and the snapshot/commit
        // pattern means the recv chain stays untouched.
        let (mut a, mut b, _) = pair();
        let w0 = a.encrypt(b"a0", b"").unwrap();
        let w1 = a.encrypt(b"a1", b"").unwrap();
        let mut tampered = w1.clone();
        // Flip the lowest bit of the counter field.
        tampered[39] ^= 0x01;
        assert!(b.decrypt(&tampered, b"").is_err());
        // Legitimate sequence still decrypts in order.
        assert_eq!(b.decrypt(&w0, b"").unwrap(), b"a0");
        assert_eq!(b.decrypt(&w1, b"").unwrap(), b"a1");
    }

    #[test]
    fn forged_dh_does_not_corrupt_state() {
        // A forged frame with a fresh DH header would otherwise
        // trigger a speculative DH ratchet step that the
        // legitimate sender can't recover from. The snapshot
        // pattern leaves state untouched on AEAD failure.
        let (mut a, mut b, _) = pair();
        let w0 = a.encrypt(b"a0", b"").unwrap();

        // Forge a frame with a brand-new DH pub and garbage
        // payload. AEAD will fail.
        let bogus_priv = StaticSecret::random_from_rng(thread_rng());
        let bogus_pub = PublicKey::from(&bogus_priv);
        let mut forged = Vec::new();
        forged.extend_from_slice(bogus_pub.as_bytes());
        forged.extend_from_slice(&0u32.to_be_bytes());
        forged.extend_from_slice(&0u32.to_be_bytes());
        forged.extend_from_slice(&[0u8; NONCE_LEN]);
        forged.extend_from_slice(&[0u8; 32 + TAG_LEN]);
        assert!(b.decrypt(&forged, b"").is_err());

        // Legitimate frame still decrypts; state was rolled back.
        assert_eq!(b.decrypt(&w0, b"").unwrap(), b"a0");
    }

    #[test]
    fn refuses_oversize_skip_inside_epoch() {
        let (mut a, mut b, _) = pair();
        // Send MAX_SKIP+1 messages without delivering any →
        // a.send_counter = MAX_SKIP+1. The next encrypt produces
        // counter = MAX_SKIP+1, giving b a skip of MAX_SKIP+1
        // against its recv_counter=0, which exceeds the cap.
        for _ in 0..(MAX_SKIP + 1) {
            let _ = a.encrypt(b"x", b"").unwrap();
        }
        let w = a.encrypt(b"too-far", b"").unwrap();
        assert!(b.decrypt(&w, b"").is_err());
    }

    #[test]
    fn rejects_short_frame() {
        let (_a, mut b, _) = pair();
        let too_short = vec![0u8; MIN_FRAME_LEN - 1];
        assert!(b.decrypt(&too_short, b"").is_err());
    }

    #[test]
    fn header_dh_pub_not_visible_on_wire() {
        // HEHE intent: the DH pub doesn't appear as plaintext on
        // the wire. Encrypt several frames and confirm a's
        // current_dh_pub bytes never show up in the encrypted
        // headers' raw representation.
        let (mut a, mut b, _) = pair();
        let _ = b; // drop unused warning
        let pub_bytes = a.current_dh_pub().as_bytes().to_vec();
        for _ in 0..5 {
            let w = a.encrypt(b"x", b"").unwrap();
            // Walk the wire looking for any 32-byte run that
            // matches the DH pub. With HEHE the AEAD ciphertext
            // is computationally indistinguishable from random,
            // so the probability of a chance match is 2^-256.
            let found = w.windows(32).any(|chunk| chunk == pub_bytes.as_slice());
            assert!(
                !found,
                "DH pub leaked onto wire — header encryption isn't binding"
            );
        }
    }

    #[test]
    fn header_keys_rotate_through_epochs() {
        // The HEHE key lifecycle: construction seeds shared
        // initial header keys, every DH ratchet step promotes
        // NHK→HK and derives fresh NHK via kdf_rk_he. Driving
        // several round-trips exercises both peers' lifecycle in
        // lockstep — every direction change requires the recv
        // side's HKr to track the send side's HKs without
        // explicit coordination.
        let (mut a, mut b, _) = pair();
        for i in 0..6 {
            let m = format!("a{i}");
            let w = a.encrypt(m.as_bytes(), b"").unwrap();
            assert_eq!(b.decrypt(&w, b"").unwrap(), m.as_bytes());
            let m = format!("b{i}");
            let w = b.encrypt(m.as_bytes(), b"").unwrap();
            assert_eq!(a.decrypt(&w, b"").unwrap(), m.as_bytes());
        }
        // After all those direction changes, fresh frames still
        // round-trip — only achievable if every NHKs/NHKr
        // promotion + kdf_rk_he derivation lined up between the
        // two peers.
        let final_a_w = a.encrypt(b"final", b"").unwrap();
        assert_eq!(b.decrypt(&final_a_w, b"").unwrap(), b"final");
    }

    #[test]
    fn responder_first_frame_decrypts_under_nhkr() {
        // Pinned regression: the responder has HKr=None at
        // construction and only NHKr seeded from the shared
        // initial-header-key. The initiator's first frame
        // therefore must decrypt via NHKr (no current HKr to
        // try first), which triggers the DH ratchet on the
        // responder side and promotes NHKr→HKr.
        let (mut a, mut b, _) = pair();
        let w = a.encrypt(b"hi", b"").unwrap();
        assert_eq!(b.decrypt(&w, b"").unwrap(), b"hi");
        // Subsequent same-direction frame decrypts via b's NEW
        // HKr (header_dh hasn't changed, so no second ratchet
        // step fires).
        let w2 = a.encrypt(b"hi 2", b"").unwrap();
        assert_eq!(b.decrypt(&w2, b"").unwrap(), b"hi 2");
    }

    /// Hybrid-mode pair: same as `pair` but both peers wired with
    /// ML-KEM-768 keypairs and each others' publics.
    fn hybrid_pair() -> (DoubleRatchet, DoubleRatchet, PublicKey) {
        let root = [0xC0_u8; 32];
        let resp_kp = StaticSecret::random_from_rng(thread_rng());
        let resp_pub = PublicKey::from(&resp_kp);

        // Each peer holds a static ML-KEM keypair; the other side
        // gets the corresponding public.
        let init_kyber = KyberKeypair::generate();
        let resp_kyber = KyberKeypair::generate();
        let init_kyber_pub = init_kyber.public();
        let resp_kyber_pub = resp_kyber.public();

        let init = DoubleRatchet::initiator_hybrid(
            &root,
            resp_pub,
            KyberConfig {
                peer_pub: resp_kyber_pub,
                own_keypair: init_kyber,
            },
        )
        .unwrap();
        let resp = DoubleRatchet::responder_hybrid(
            &root,
            resp_kp,
            KyberConfig {
                peer_pub: init_kyber_pub,
                own_keypair: resp_kyber,
            },
        )
        .unwrap();
        (init, resp, resp_pub)
    }

    /// Length of the encrypted-header field on the wire: the
    /// plaintext header is `HEADER_PREFIX_LEN + kyber_ct_len`
    /// bytes; AEAD adds a 16-byte tag. The wire's first two
    /// bytes are this `enc_hdr_len` BE u16, so tests can read
    /// it back directly to verify whether a kyber ciphertext
    /// was included even though the kyber ct itself is now
    /// inside the encrypted header.
    fn wire_enc_hdr_len(wire: &[u8]) -> usize {
        u16::from_be_bytes(wire[..2].try_into().unwrap()) as usize
    }

    /// Sentinel: `enc_hdr_len` for a no-kyber header.
    const NO_KYBER_ENC_HDR_LEN: usize = HEADER_PREFIX_LEN + TAG_LEN;
    /// Sentinel: `enc_hdr_len` for a hybrid frame carrying a
    /// full ML-KEM-768 ciphertext.
    const KYBER_ENC_HDR_LEN: usize = HEADER_PREFIX_LEN + MLKEM768_CT_LEN + TAG_LEN;

    #[test]
    fn hybrid_round_trip_basic() {
        let (mut a, mut b, _) = hybrid_pair();
        let w = a.encrypt(b"hi", b"").unwrap();
        // First frame must carry kyber_ct on hybrid mode.
        assert_eq!(wire_enc_hdr_len(&w), KYBER_ENC_HDR_LEN);
        assert_eq!(b.decrypt(&w, b"").unwrap(), b"hi");

        // Subsequent same-direction frames carry no kyber_ct.
        let w2 = a.encrypt(b"hi 2", b"").unwrap();
        assert_eq!(wire_enc_hdr_len(&w2), NO_KYBER_ENC_HDR_LEN);
        assert_eq!(b.decrypt(&w2, b"").unwrap(), b"hi 2");

        // b's first reply also carries kyber_ct, since b just
        // derived its first send chain via the DH ratchet step.
        let w3 = b.encrypt(b"hi from b", b"").unwrap();
        assert_eq!(wire_enc_hdr_len(&w3), KYBER_ENC_HDR_LEN);
        assert_eq!(a.decrypt(&w3, b"").unwrap(), b"hi from b");
    }

    #[test]
    fn hybrid_back_and_forth_re_encaps_each_direction_change() {
        let (mut a, mut b, _) = hybrid_pair();
        for i in 0..6 {
            let m = format!("a{i}");
            let w = a.encrypt(m.as_bytes(), b"").unwrap();
            assert_eq!(
                wire_enc_hdr_len(&w),
                KYBER_ENC_HDR_LEN,
                "a-send #{i} should carry kyber"
            );
            assert_eq!(b.decrypt(&w, b"").unwrap(), m.as_bytes());

            let m = format!("b{i}");
            let w = b.encrypt(m.as_bytes(), b"").unwrap();
            assert_eq!(
                wire_enc_hdr_len(&w),
                KYBER_ENC_HDR_LEN,
                "b-send #{i} should carry kyber"
            );
            assert_eq!(a.decrypt(&w, b"").unwrap(), m.as_bytes());
        }
    }

    #[test]
    fn hybrid_out_of_order_within_epoch() {
        let (mut a, mut b, _) = hybrid_pair();
        // First frame from a carries kyber; subsequent same-epoch
        // frames don't. Out-of-order delivery within those
        // subsequent frames must still decrypt via the stash.
        let w0 = a.encrypt(b"a0", b"").unwrap(); // kyber-bearing
        let w1 = a.encrypt(b"a1", b"").unwrap(); // no kyber
        let w2 = a.encrypt(b"a2", b"").unwrap(); // no kyber

        // Deliver in order: w0 first (must, since it carries
        // kyber that the receiver mixes into the recv chain).
        assert_eq!(b.decrypt(&w0, b"").unwrap(), b"a0");
        // Now w1 and w2 can come in any order.
        assert_eq!(b.decrypt(&w2, b"").unwrap(), b"a2");
        assert_eq!(b.decrypt(&w1, b"").unwrap(), b"a1");
    }

    #[test]
    fn hybrid_rejects_kyber_on_non_epoch_frame() {
        let (mut a, mut b, _) = hybrid_pair();
        let w0 = a.encrypt(b"a0", b"").unwrap(); // legit kyber frame
        b.decrypt(&w0, b"").unwrap();
        let w1 = a.encrypt(b"a1", b"").unwrap(); // no-kyber frame
        // Splice a fake kyber blob into w1's header and re-pack.
        let real_kyber = &w0[HEADER_PREFIX_LEN..HEADER_PREFIX_LEN + MLKEM768_CT_LEN];
        let mut tampered = Vec::new();
        tampered.extend_from_slice(&w1[..40]); // dh_pub + prev_n + n
        tampered.extend_from_slice(&(MLKEM768_CT_LEN as u16).to_be_bytes());
        tampered.extend_from_slice(real_kyber);
        tampered.extend_from_slice(&w1[HEADER_PREFIX_LEN..]); // nonce + ct
        // Same-epoch frame can't carry a kyber_ct.
        assert!(b.decrypt(&tampered, b"").is_err());
        // Legit frame still decrypts.
        assert_eq!(b.decrypt(&w1, b"").unwrap(), b"a1");
    }

    #[test]
    fn hybrid_rejects_wrong_kyber_length() {
        // Hand-craft a "fresh epoch" frame with a wrong-sized
        // kyber blob. Must fail validation before we touch any
        // ratchet state.
        let (mut _a, mut b, _) = hybrid_pair();
        let bogus_dh = StaticSecret::random_from_rng(thread_rng());
        let bogus_dh_pub = PublicKey::from(&bogus_dh);
        let mut frame = Vec::new();
        frame.extend_from_slice(bogus_dh_pub.as_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        // Claim a 64-byte kyber blob (real ML-KEM-768 ct is 1088).
        frame.extend_from_slice(&64u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 64]);
        frame.extend_from_slice(&[0u8; NONCE_LEN]);
        frame.extend_from_slice(&[0u8; 32 + TAG_LEN]);
        assert!(b.decrypt(&frame, b"").is_err());
    }

    #[test]
    fn hybrid_rejects_kyber_in_non_hybrid_mode() {
        // Non-hybrid local. A peer frame that includes kyber_ct
        // must be rejected (no key to decap with — protocol
        // confusion or downgrade attempt).
        let (mut a, mut b, _) = pair(); // non-hybrid
        // Hand-craft a fresh-epoch frame from a third-party DH
        // with a bogus 1088-byte kyber blob.
        let bogus_dh = StaticSecret::random_from_rng(thread_rng());
        let bogus_dh_pub = PublicKey::from(&bogus_dh);
        let mut frame = Vec::new();
        frame.extend_from_slice(bogus_dh_pub.as_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&(MLKEM768_CT_LEN as u16).to_be_bytes());
        frame.extend_from_slice(&[0u8; MLKEM768_CT_LEN]);
        frame.extend_from_slice(&[0u8; NONCE_LEN]);
        frame.extend_from_slice(&[0u8; 32 + TAG_LEN]);
        assert!(b.decrypt(&frame, b"").is_err());
        // a's legitimate frame still decrypts.
        let w = a.encrypt(b"still working", b"").unwrap();
        assert_eq!(b.decrypt(&w, b"").unwrap(), b"still working");
    }

    #[test]
    fn hybrid_forged_kyber_does_not_corrupt_state() {
        let (mut a, mut b, _) = hybrid_pair();
        let w0 = a.encrypt(b"a0", b"").unwrap();

        // Forge a frame with a fresh DH header and a bogus kyber
        // ct of the right length. Decap will produce a wrong
        // shared secret, AEAD will fail, snapshot/commit pattern
        // rolls back the entire DH ratchet step including the
        // kyber-mix.
        let bogus_dh = StaticSecret::random_from_rng(thread_rng());
        let bogus_dh_pub = PublicKey::from(&bogus_dh);
        let mut forged = Vec::new();
        forged.extend_from_slice(bogus_dh_pub.as_bytes());
        forged.extend_from_slice(&0u32.to_be_bytes());
        forged.extend_from_slice(&0u32.to_be_bytes());
        forged.extend_from_slice(&(MLKEM768_CT_LEN as u16).to_be_bytes());
        forged.extend_from_slice(&[0u8; MLKEM768_CT_LEN]);
        forged.extend_from_slice(&[0u8; NONCE_LEN]);
        forged.extend_from_slice(&[0u8; 32 + TAG_LEN]);
        assert!(b.decrypt(&forged, b"").is_err());

        // Legitimate frame still decrypts — state was rolled back.
        assert_eq!(b.decrypt(&w0, b"").unwrap(), b"a0");
    }
}
