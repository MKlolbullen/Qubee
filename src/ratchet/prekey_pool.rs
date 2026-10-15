//! Versioned, bounded one-time X25519/ML-KEM pairs and signed-prekey epochs.
//! All secret transitions belong to the caller's keystore transaction. A public
//! pool is not an allocation service: independent initiators can collide and
//! must refresh/retry; the responder never reuses an already consumed pair.
use anyhow::{anyhow, ensure, Result};
use pqcrypto_mlkem::mlkem768::{keypair, PublicKey as KemPublic, SecretKey as KemSecret};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::groups::group_handshake::{GroupHandshake, PREKEY_BUNDLE_MAX_AGE_SECS};
use crate::identity::identity_key::{HybridSignature, IdentityId, IdentityKey, IdentityKeyPair};
use crate::ratchet::pqxdh::{PrekeyBundlePublic, PrekeyBundleSecret};
use crate::storage::secure_keystore::{KeyMetadata, KeyType, KeyUsage, SecureKeyStore};

pub const POOL_SIZE: usize = 32;
pub const ROTATION_SECS: u64 = 7 * 24 * 60 * 60;
const RETENTION_SECS: u64 = PREKEY_BUNDLE_MAX_AGE_SECS + 60;
const MAX_EPOCHS: usize = 8;
pub(crate) const LOCAL: &str = "ratchet_local_prekey_pool_v2";
const PEER: &str = "ratchet_pool_peer_";
const USED: &str = "ratchet_pool_reserved_";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrekeySelection {
    pub epoch: u64,
    pub id: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OneTimePublic {
    pub id: [u8; 16],
    pub x25519: [u8; 32],
    pub kem_public: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolBody {
    pub publisher: IdentityKey,
    pub identity_x25519: [u8; 32],
    pub epoch: u64,
    pub signed_prekey: [u8; 32],
    pub created_at: u64,
    pub timestamp: u64,
    pub prekeys: Vec<OneTimePublic>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredPair {
    id: [u8; 16],
    x25519: [u8; 32],
    kem_secret: Vec<u8>,
    kem_public: Vec<u8>,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredEpoch {
    id: u64,
    created_at: u64,
    retired_at: Option<u64>,
    signed_prekey: [u8; 32],
    // Includes IDs of consumed pairs so replenishment cannot reuse an ID.
    issued_ids: Vec<[u8; 16]>,
    pairs: Vec<StoredPair>,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredPool {
    identity: [u8; 32],
    legacy_until: u64,
    last_seen: u64,
    epochs: Vec<StoredEpoch>,
}
#[derive(Serialize, Deserialize)]
struct Reservations {
    epoch: u64,
    ids: Vec<[u8; 16]>,
}
fn key(prefix: &str, id: &IdentityId) -> String {
    format!("{prefix}{}", hex::encode(id.as_ref()))
}
fn metadata() -> KeyMetadata {
    KeyMetadata {
        algorithm: "qubee-pool-v2-x25519+mlkem768".into(),
        key_size: 32,
        usage: vec![KeyUsage::KeyAgreement],
        expiry: None,
        tags: std::collections::HashMap::new(),
    }
}
fn put<T: Serialize>(ks: &mut SecureKeyStore, id: &str, value: &T) -> Result<()> {
    let bytes = Zeroizing::new(bincode::serialize(value)?);
    ks.store_key(id, &bytes, KeyType::PreKey, metadata())
}
fn new_epoch(id: u64, now: u64) -> Result<StoredEpoch> {
    Ok(StoredEpoch {
        id,
        created_at: now,
        retired_at: None,
        signed_prekey: crate::security::secure_rng::random::array()?,
        issued_ids: Vec::new(),
        pairs: Vec::new(),
    })
}
fn replenish(epoch: &mut StoredEpoch) -> Result<()> {
    // Bound total issuance too; exhausting this epoch rotates it on publication.
    while epoch.pairs.len() < POOL_SIZE && epoch.issued_ids.len() < POOL_SIZE * 4 {
        let id = crate::security::secure_rng::random::array()?;
        if epoch.issued_ids.contains(&id) {
            continue;
        }
        let (public, secret) = keypair();
        epoch.pairs.push(StoredPair {
            id,
            x25519: crate::security::secure_rng::random::array()?,
            kem_secret: secret.as_bytes().to_vec(),
            kem_public: public.as_bytes().to_vec(),
        });
        epoch.issued_ids.push(id);
    }
    Ok(())
}
fn load(ks: &mut SecureKeyStore, now: u64) -> Result<StoredPool> {
    if let Some(secret) = ks.retrieve_key(LOCAL, KeyUsage::KeyAgreement)? {
        let pool: StoredPool = bincode::deserialize(secret.expose_secret())?;
        ensure!(
            !pool.epochs.is_empty() && pool.epochs.len() <= MAX_EPOCHS,
            "invalid stored prekey epoch count"
        );
        ensure!(
            pool.last_seen.saturating_sub(now) <= IdentityKey::MAX_CLOCK_SKEW_SECS,
            "clock rollback while managing prekeys"
        );
        for e in &pool.epochs {
            ensure!(
                e.pairs.len() <= POOL_SIZE && e.issued_ids.len() <= POOL_SIZE * 4,
                "invalid stored prekey pool size"
            );
        }
        return Ok(pool);
    }
    // Preserve the existing deniable X25519 identity across v1 -> v2 migration.
    let (legacy, _) = super::prekey_store::get_or_create_local_bundle(ks, now)?;
    Ok(StoredPool {
        identity: legacy.identity.to_bytes(),
        legacy_until: now.saturating_add(RETENTION_SECS),
        last_seen: now,
        epochs: vec![new_epoch(1, now)?],
    })
}

fn save_pool(ks: &mut SecureKeyStore, pool: &StoredPool) -> Result<()> {
    if pool.last_seen > pool.legacy_until {
        super::prekey_store::retire_legacy_bundle(ks)?;
    }
    put(ks, LOCAL, pool)
}
fn maintain(pool: &mut StoredPool, now: u64, refill: bool) -> Result<()> {
    let now = now.max(pool.last_seen);
    pool.last_seen = now;
    pool.epochs.retain(|e| {
        e.retired_at
            .is_none_or(|t| now.saturating_sub(t) <= RETENTION_SECS)
    });
    let current = pool
        .epochs
        .last_mut()
        .ok_or_else(|| anyhow!("no current prekey epoch"))?;
    if now.saturating_sub(current.created_at) >= ROTATION_SECS
        || (refill && current.pairs.is_empty() && current.issued_ids.len() >= POOL_SIZE * 4)
    {
        let next = current
            .id
            .checked_add(1)
            .ok_or_else(|| anyhow!("prekey epoch exhausted"))?;
        // Long suspension must not restart the retention clock for old keys.
        current.retired_at = Some(now.min(current.created_at.saturating_add(ROTATION_SECS)));
        ensure!(
            pool.epochs.len() < MAX_EPOCHS,
            "retained prekey epoch limit reached"
        );
        pool.epochs.push(new_epoch(next, now)?);
    }
    pool.epochs.retain(|e| {
        e.retired_at
            .is_none_or(|t| now.saturating_sub(t) <= RETENTION_SECS)
    });
    if refill {
        replenish(pool.epochs.last_mut().unwrap())?;
    }
    Ok(())
}
/// Publish current public material, rotating on age and replenishing the pool.
/// The enclosing transaction commits publication state only if signing succeeds.
pub fn publish(ks: &mut SecureKeyStore, signer: &IdentityKeyPair, now: u64) -> Result<Vec<u8>> {
    ks.transaction(|ks| {
        let mut pool = load(ks, now)?;
        maintain(&mut pool, now, true)?;
        let epoch = pool.epochs.last().unwrap();
        let body = PoolBody {
            publisher: signer.public_key(),
            identity_x25519: *PublicKey::from(&StaticSecret::from(pool.identity)).as_bytes(),
            epoch: epoch.id,
            signed_prekey: *PublicKey::from(&StaticSecret::from(epoch.signed_prekey)).as_bytes(),
            created_at: epoch.created_at,
            timestamp: pool.last_seen,
            prekeys: epoch
                .pairs
                .iter()
                .map(|p| OneTimePublic {
                    id: p.id,
                    x25519: *PublicKey::from(&StaticSecret::from(p.x25519)).as_bytes(),
                    kem_public: p.kem_public.clone(),
                })
                .collect(),
        };
        let wire = sign(signer, body)?.to_wire()?;
        save_pool(ks, &pool)?;
        Ok(wire)
    })
}
pub fn canonical(body: &PoolBody) -> Result<Vec<u8>> {
    let mut bytes = b"qubee_prekey_pool_v2\0".to_vec();
    bytes.extend_from_slice(&bincode::serialize(body)?);
    Ok(bytes)
}
fn validate(body: &PoolBody) -> Result<()> {
    body.publisher.validate()?;
    ensure!(
        body.epoch > 0 && !body.prekeys.is_empty() && body.prekeys.len() <= POOL_SIZE,
        "invalid published prekey pool size or epoch"
    );
    ensure!(
        body.created_at <= body.timestamp && body.timestamp - body.created_at < ROTATION_SECS,
        "prekey publication outlived its rotation epoch"
    );
    let mut ids = std::collections::HashSet::new();
    let mut dhs = std::collections::HashSet::new();
    let mut kems = std::collections::HashSet::new();
    let probe = StaticSecret::from([0x42; 32]);
    crate::security::key_agreement::checked_x25519(&probe, &PublicKey::from(body.identity_x25519))?;
    crate::security::key_agreement::checked_x25519(&probe, &PublicKey::from(body.signed_prekey))?;
    for p in &body.prekeys {
        ensure!(
            ids.insert(p.id) && dhs.insert(p.x25519) && kems.insert(p.kem_public.as_slice()),
            "duplicate prekey ID or key in pool"
        );
        crate::security::key_agreement::checked_x25519(&probe, &PublicKey::from(p.x25519))?;
        let public = KemPublic::from_bytes(&p.kem_public)
            .map_err(|e| anyhow!("invalid pool KEM key: {e}"))?;
        super::pqxdh::validate_kem_public(&public)?;
    }
    Ok(())
}
pub fn sign(signer: &IdentityKeyPair, body: PoolBody) -> Result<GroupHandshake> {
    validate(&body)?;
    ensure!(
        body.publisher == signer.public_key(),
        "pool publisher does not match signer"
    );
    let signature = signer.sign(&canonical(&body)?)?;
    Ok(GroupHandshake::PrekeyPool { body, signature })
}
pub fn verify(body: &PoolBody, signature: &HybridSignature) -> Result<bool> {
    validate(body)?;
    body.publisher
        .verify_with_max_age(&canonical(body)?, signature, PREKEY_BUNDLE_MAX_AGE_SECS)
}
pub fn peer(ks: &mut SecureKeyStore, id: &IdentityId) -> Result<Option<PoolBody>> {
    let Some(secret) = ks.retrieve_key(&key(PEER, id), KeyUsage::KeyAgreement)? else {
        return Ok(None);
    };
    let body: PoolBody = bincode::deserialize(secret.expose_secret())?;
    ensure!(
        body.publisher.identity_id == *id,
        "cached pool identity mismatch"
    );
    validate(&body)?;
    Ok(Some(body))
}
pub fn fresh_peer(ks: &mut SecureKeyStore, id: &IdentityId, now: u64) -> Result<Option<PoolBody>> {
    let body = peer(ks, id)?;
    if let Some(b) = &body {
        ensure!(
            b.timestamp.saturating_sub(now) <= IdentityKey::MAX_CLOCK_SKEW_SECS,
            "cached prekey pool timestamp is in the future"
        );
        ensure!(
            now.saturating_sub(b.timestamp) <= PREKEY_BUNDLE_MAX_AGE_SECS,
            "cached prekey pool expired; refresh before establishment"
        );
    }
    Ok(body)
}
pub fn install(
    ks: &mut SecureKeyStore,
    body: &PoolBody,
    signature: &HybridSignature,
) -> Result<()> {
    ensure!(
        verify(body, signature)?,
        "prekey pool signature verification failed"
    );
    if let Some(old) = peer(ks, &body.publisher.identity_id)? {
        ensure!(
            body.timestamp >= old.timestamp && body.epoch >= old.epoch,
            "prekey pool rollback"
        );
        ensure!(
            body.identity_x25519 == old.identity_x25519,
            "deniable identity key changed"
        );
        if body.epoch == old.epoch {
            ensure!(
                body.signed_prekey == old.signed_prekey && body.created_at == old.created_at,
                "prekey epoch equivocation"
            );
            for p in &body.prekeys {
                if let Some(previous) = old.prekeys.iter().find(|q| q.id == p.id) {
                    ensure!(p == previous, "prekey ID equivocation");
                }
            }
        }
    } else if let Some(old) = super::prekey_store::get_peer_bundle(ks, &body.publisher.identity_id)?
    {
        ensure!(
            body.timestamp >= old.timestamp && body.identity_x25519 == old.identity_x25519,
            "legacy prekey migration rollback or identity change"
        );
    }
    put(ks, &key(PEER, &body.publisher.identity_id), body)
}
pub fn peer_ids(ks: &SecureKeyStore) -> Result<Vec<IdentityId>> {
    ks.list_keys()
        .into_iter()
        .filter_map(|s| s.strip_prefix(PEER).map(str::to_owned))
        .map(|s| {
            let bytes = hex::decode(s)?;
            Ok(IdentityId::from(
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| anyhow!("invalid cached pool identity"))?,
            ))
        })
        .collect()
}
/// Local reservation reduces repeated selection by this device. It cannot
/// allocate a public key globally across independent decentralized initiators.
pub fn reserve(
    ks: &mut SecureKeyStore,
    body: &PoolBody,
) -> Result<(PrekeySelection, PrekeyBundlePublic)> {
    let name = key(USED, &body.publisher.identity_id);
    let mut used = match ks.retrieve_key(&name, KeyUsage::KeyAgreement)? {
        Some(s) => bincode::deserialize::<Reservations>(s.expose_secret())?,
        None => Reservations {
            epoch: body.epoch,
            ids: Vec::new(),
        },
    };
    ensure!(used.epoch <= body.epoch, "reservation epoch rollback");
    if used.epoch != body.epoch {
        used = Reservations {
            epoch: body.epoch,
            ids: Vec::new(),
        };
    }
    ensure!(
        used.ids.len() <= POOL_SIZE * 4,
        "invalid local prekey reservations"
    );
    let available: Vec<_> = body
        .prekeys
        .iter()
        .filter(|p| !used.ids.contains(&p.id))
        .collect();
    ensure!(
        !available.is_empty(),
        "peer prekey pool exhausted; refresh required"
    );
    let random: [u8; 8] = crate::security::secure_rng::random::array()?;
    // Tiny modulo bias is irrelevant for secrecy; keys themselves are secure RNG output.
    let p = available[(u64::from_le_bytes(random) % available.len() as u64) as usize];
    ensure!(
        used.ids.len() < POOL_SIZE * 4,
        "prekey reservation limit reached; rotate peer epoch"
    );
    used.ids.push(p.id);
    put(ks, &name, &used)?;
    Ok((
        PrekeySelection {
            epoch: body.epoch,
            id: p.id,
        },
        PrekeyBundlePublic {
            identity: PublicKey::from(body.identity_x25519),
            signed_prekey: PublicKey::from(body.signed_prekey),
            one_time_prekey: Some(PublicKey::from(p.x25519)),
            kem_public: KemPublic::from_bytes(&p.kem_public)
                .map_err(|e| anyhow!("invalid KEM key: {e}"))?,
        },
    ))
}
pub fn local_identity(ks: &mut SecureKeyStore, now: u64) -> Result<StaticSecret> {
    let pool = load(ks, now)?;
    // Persist migration even if this device has not published a pool yet.
    save_pool(ks, &pool)?;
    Ok(StaticSecret::from(pool.identity))
}
pub fn responder_secret(
    ks: &mut SecureKeyStore,
    selection: &PrekeySelection,
    now: u64,
) -> Result<PrekeyBundleSecret> {
    let mut pool = load(ks, now)?;
    maintain(&mut pool, now, false)?;
    let epoch = pool
        .epochs
        .iter()
        .find(|e| e.id == selection.epoch)
        .ok_or_else(|| anyhow!("unknown or expired prekey epoch"))?;
    let pair = epoch
        .pairs
        .iter()
        .find(|p| p.id == selection.id)
        .ok_or_else(|| anyhow!("unknown or consumed one-time prekey ID; refresh required"))?;
    let result = PrekeyBundleSecret {
        identity: StaticSecret::from(pool.identity),
        signed_prekey: StaticSecret::from(epoch.signed_prekey),
        one_time_prekey: Some(StaticSecret::from(pair.x25519)),
        kem_secret: KemSecret::from_bytes(&pair.kem_secret)
            .map_err(|e| anyhow!("invalid KEM secret: {e}"))?,
    };
    save_pool(ks, &pool)?;
    Ok(result)
}
pub fn consume(ks: &mut SecureKeyStore, selection: &PrekeySelection, now: u64) -> Result<()> {
    let mut pool = load(ks, now)?;
    let epoch = pool
        .epochs
        .iter_mut()
        .find(|e| e.id == selection.epoch)
        .ok_or_else(|| anyhow!("unknown prekey epoch"))?;
    let index = epoch
        .pairs
        .iter()
        .position(|p| p.id == selection.id)
        .ok_or_else(|| anyhow!("one-time prekey already consumed"))?;
    // Drop zeroizes the X25519 seed and serialized KEM secret.
    epoch.pairs.remove(index);
    save_pool(ks, &pool)
}
/// Domain separation and transcript binding for the new setup. The session
/// layer binds this together with the two identities into its initial KDF.
pub fn context(selection: &PrekeySelection) -> Vec<u8> {
    let mut out = b"qubee_pool_selection_v2\0".to_vec();
    out.extend_from_slice(&selection.epoch.to_le_bytes());
    out.extend_from_slice(&selection.id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::direct::{
        decrypt_direct, encrypt_direct, install_peer_bundle, reset_direct_session,
    };
    use crate::ratchet::direct_message::{DirectMessage, MAGIC_POOL_DIRECT_MESSAGE};
    use crate::ratchet::session::load_session;
    use tempfile::TempDir;

    struct Device {
        dir: TempDir,
        ks: SecureKeyStore,
        signer: IdentityKeyPair,
    }
    impl Device {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let ks = SecureKeyStore::new(dir.path().join("pool.db"), b"pool-test").unwrap();
            Self {
                dir,
                ks,
                signer: IdentityKeyPair::generate().unwrap(),
            }
        }
        fn id(&self) -> IdentityId {
            self.signer.identity_id()
        }
        fn body(&mut self, now: u64) -> PoolBody {
            let wire = publish(&mut self.ks, &self.signer, now).unwrap();
            match GroupHandshake::from_wire(&wire).unwrap() {
                GroupHandshake::PrekeyPool { body, .. } => body,
                _ => panic!("unexpected frame"),
            }
        }
        fn install(&mut self, body: PoolBody, signer: &IdentityKeyPair) {
            install_peer_bundle(
                &mut self.ks,
                &sign(signer, body).unwrap().to_wire().unwrap(),
            )
            .unwrap();
        }
        fn bytes(&self) -> Vec<u8> {
            std::fs::read(self.dir.path().join("pool.db")).unwrap()
        }
        fn reload(&mut self) {
            self.ks = SecureKeyStore::new(self.dir.path().join("pool.db"), b"pool-test").unwrap();
        }
    }
    fn paired() -> (Device, Device) {
        let (mut a, mut b) = (Device::new(), Device::new());
        let (ab, bb) = (a.body(1), b.body(1));
        a.install(bb, &b.signer);
        b.install(ab, &a.signer);
        (a, b)
    }
    #[test]
    fn publication_survives_reload_preserves_identity_and_rotates_at_boundary() {
        let mut d = Device::new();
        let (legacy, _) =
            super::super::prekey_store::get_or_create_local_bundle(&mut d.ks, 1).unwrap();
        let first = d.body(1);
        assert_eq!(
            first.identity_x25519,
            *PublicKey::from(&legacy.identity).as_bytes()
        );
        assert_eq!(first.prekeys.len(), POOL_SIZE);
        d.reload();
        let before = d.body(ROTATION_SECS);
        assert_eq!(first.epoch, before.epoch);
        assert_eq!(first.prekeys, before.prekeys);
        let next = d.body(1 + ROTATION_SECS);
        assert_eq!(next.epoch, first.epoch + 1);
        assert_eq!(next.identity_x25519, first.identity_x25519);
        assert_ne!(next.signed_prekey, first.signed_prekey);
        assert!(next.prekeys.iter().all(|p| !first.prekeys.contains(p)));
    }
    #[test]
    fn two_initiators_consume_only_their_selected_x25519_and_kem_pairs() {
        let (mut a, mut b, mut c) = (Device::new(), Device::new(), Device::new());
        let (ab, mut bb, cb) = (a.body(1), b.body(1), c.body(1));
        b.install(ab, &a.signer);
        b.install(cb, &c.signer);
        let mut second = bb.clone();
        second.prekeys = vec![bb.prekeys[1].clone()];
        bb.prekeys.truncate(1);
        a.install(bb, &b.signer);
        c.install(second, &b.signer);
        let (aid, bid, cid) = (a.id(), b.id(), c.id());
        let wa = encrypt_direct(&mut a.ks, aid, bid, b"alice", 2).unwrap();
        let wc = encrypt_direct(&mut c.ks, cid, bid, b"charlie", 2).unwrap();
        assert!(wa.starts_with(MAGIC_POOL_DIRECT_MESSAGE));
        let sa = DirectMessage::from_wire(&wa)
            .unwrap()
            .prekey_selection
            .unwrap();
        let sc = DirectMessage::from_wire(&wc)
            .unwrap()
            .prekey_selection
            .unwrap();
        assert_ne!(sa.id, sc.id);
        assert_eq!(decrypt_direct(&mut b.ks, bid, &wa, 2).unwrap().1, b"alice");
        b.reload();
        assert_eq!(
            decrypt_direct(&mut b.ks, bid, &wc, 2).unwrap().1,
            b"charlie"
        );
        let pool = load(&mut b.ks, 2).unwrap();
        let pairs = &pool.epochs.last().unwrap().pairs;
        assert_eq!(pairs.len(), POOL_SIZE - 2);
        assert!(pairs.iter().all(|p| p.id != sa.id && p.id != sc.id));
        assert!(responder_secret(&mut b.ks, &sa, 2).is_err());
        let refreshed = b.body(3);
        assert_eq!(refreshed.prekeys.len(), POOL_SIZE);
        assert!(refreshed
            .prekeys
            .iter()
            .all(|p| p.id != sa.id && p.id != sc.id));
    }
    #[test]
    fn invalid_and_replayed_initials_do_not_burn_prekeys_or_commit_state() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.id(), b.id());
        let wire = encrypt_direct(&mut a.ks, aid, bid, b"authenticated", 2).unwrap();
        let before = b.bytes();
        for mode in 0..3 {
            let mut dm = DirectMessage::from_wire(&wire).unwrap();
            match mode {
                0 => dm.ciphertext[0] ^= 1,
                1 => dm.prekey_selection.as_mut().unwrap().id = [0; 16],
                _ => dm.prekey_selection.as_mut().unwrap().epoch += 1,
            }
            assert!(decrypt_direct(&mut b.ks, bid, &dm.to_wire().unwrap(), 2).is_err());
            assert_eq!(b.bytes(), before);
            assert!(load_session(&mut b.ks, &aid).unwrap().is_none());
        }
        b.reload();
        assert_eq!(
            decrypt_direct(&mut b.ks, bid, &wire, 2).unwrap().1,
            b"authenticated"
        );
        let accepted = b.bytes();
        assert!(decrypt_direct(&mut b.ks, bid, &wire, 2).is_err());
        assert_eq!(b.bytes(), accepted);
    }
    #[test]
    fn rotated_epoch_opens_delayed_initial_but_expired_epoch_is_rejected() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.id(), b.id());
        let wire = encrypt_direct(&mut a.ks, aid, bid, b"delayed", 2).unwrap();
        b.body(1 + ROTATION_SECS);
        b.reload();
        assert_eq!(
            decrypt_direct(&mut b.ks, bid, &wire, 1 + ROTATION_SECS)
                .unwrap()
                .1,
            b"delayed"
        );
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.id(), b.id());
        let wire = encrypt_direct(&mut a.ks, aid, bid, b"too late", 2).unwrap();
        let late = 1 + ROTATION_SECS + RETENTION_SECS + 1;
        b.body(late); // Prunes old keys even after one long suspension.
        let refreshed = a.body(late);
        b.install(refreshed, &a.signer);
        let before = b.bytes();
        assert!(decrypt_direct(&mut b.ks, bid, &wire, late)
            .unwrap_err()
            .to_string()
            .contains("epoch"));
        assert_eq!(b.bytes(), before);
        assert_eq!(load(&mut b.ks, late).unwrap().epochs.len(), 1);
    }
    #[test]
    fn established_sessions_survive_prekey_rotation_expiry_and_reload() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.id(), b.id());
        let w = encrypt_direct(&mut a.ks, aid, bid, b"initial", 2).unwrap();
        decrypt_direct(&mut b.ks, bid, &w, 2).unwrap();
        let w = encrypt_direct(&mut b.ks, bid, aid, b"confirm", 2).unwrap();
        decrypt_direct(&mut a.ks, aid, &w, 2).unwrap();
        let late = 1 + ROTATION_SECS + RETENTION_SECS + 1;
        a.body(late);
        b.body(late);
        a.reload();
        b.reload();
        let w = encrypt_direct(&mut a.ks, aid, bid, b"existing", late).unwrap();
        assert!(DirectMessage::from_wire(&w)
            .unwrap()
            .prekey_selection
            .is_none());
        assert_eq!(
            decrypt_direct(&mut b.ks, bid, &w, late).unwrap().1,
            b"existing"
        );
    }
    #[test]
    fn local_reservations_survive_reset_and_refuse_exhausted_or_expired_pools() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.id(), b.id());
        let mut ids = std::collections::HashSet::new();
        for _ in 0..POOL_SIZE {
            let w = encrypt_direct(&mut a.ks, aid, bid, b"reserve", 2).unwrap();
            let s = DirectMessage::from_wire(&w)
                .unwrap()
                .prekey_selection
                .unwrap();
            assert!(ids.insert(s.id));
            reset_direct_session(&mut a.ks, &bid).unwrap();
        }
        a.reload();
        let before = a.bytes();
        assert!(encrypt_direct(&mut a.ks, aid, bid, b"empty", 2)
            .unwrap_err()
            .to_string()
            .contains("exhausted"));
        assert_eq!(a.bytes(), before);
        // Republishing unchanged keys cannot clear the local reservation ledger.
        let body = b.body(3);
        a.install(body, &b.signer);
        assert!(encrypt_direct(&mut a.ks, aid, bid, b"still empty", 3).is_err());
        let late = PREKEY_BUNDLE_MAX_AGE_SECS + 4;
        let before = a.bytes();
        assert!(encrypt_direct(&mut a.ks, aid, bid, b"expired", late)
            .unwrap_err()
            .to_string()
            .contains("expired"));
        assert_eq!(a.bytes(), before);
    }
    #[test]
    fn duplicate_keys_tampering_rollback_and_protocol_downgrade_fail_closed() {
        let (mut a, mut b) = paired();
        let body = b.body(2);
        let mut duplicate = body.clone();
        duplicate.prekeys[1] = duplicate.prekeys[0].clone();
        assert!(sign(&b.signer, duplicate).is_err());
        let mut frame = sign(&b.signer, body.clone()).unwrap();
        if let GroupHandshake::PrekeyPool { body, .. } = &mut frame {
            body.epoch += 1;
        }
        let before = a.bytes();
        assert!(install_peer_bundle(&mut a.ks, &frame.to_wire().unwrap()).is_err());
        assert_eq!(a.bytes(), before);
        let rotated = b.body(ROTATION_SECS + 1);
        a.install(rotated, &b.signer);
        assert!(install_peer_bundle(
            &mut a.ks,
            &sign(&b.signer, body).unwrap().to_wire().unwrap()
        )
        .is_err());
        let (legacy, kem) =
            super::super::prekey_store::get_or_create_local_bundle(&mut b.ks, 2).unwrap();
        let legacy = crate::groups::group_handshake::sign_prekey_bundle(
            &b.signer,
            super::super::prekey_store::build_body(
                &legacy,
                &kem,
                b.signer.public_key(),
                ROTATION_SECS + 2,
            ),
        )
        .unwrap();
        assert!(install_peer_bundle(&mut a.ks, &legacy.to_wire().unwrap()).is_err());
    }
    #[test]
    fn selection_context_is_bound_even_when_public_key_material_is_identical() {
        let mut b = Device::new();
        let body = b.body(1);
        let selection = PrekeySelection {
            epoch: body.epoch,
            id: body.prekeys[0].id,
        };
        let secret = responder_secret(&mut b.ks, &selection, 1).unwrap();
        let p = &body.prekeys[0];
        let public = PrekeyBundlePublic {
            identity: PublicKey::from(body.identity_x25519),
            signed_prekey: PublicKey::from(body.signed_prekey),
            one_time_prekey: Some(PublicKey::from(p.x25519)),
            kem_public: KemPublic::from_bytes(&p.kem_public).unwrap(),
        };
        let aid = IdentityId::from([0x11; 32]);
        let bid = b.id();
        let identity = StaticSecret::from([0x22; 32]);
        let (mut a, initial) = super::super::session::Session::establish_initiator_bound(
            aid,
            bid,
            &identity,
            &public,
            Some(&context(&selection)),
        )
        .unwrap();
        let mut other = selection;
        other.id[0] ^= 1;
        let mut b = super::super::session::Session::establish_responder_bound(
            bid,
            aid,
            &secret,
            &initial,
            Some(&context(&other)),
        )
        .unwrap();
        let (h, c) = a.encrypt(b"bound").unwrap();
        assert!(b.decrypt(&h, &c).is_err());
    }
}
