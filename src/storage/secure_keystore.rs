use crate::security::secure_rng;
use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Magic prefix of the v2 `.master` file layout:
/// `"QKM2" || salt(16) || nonce(12) || ciphertext`.
///
/// v2 wraps the master key under **Argon2id(passphrase, salt)** with a
/// per-install random salt stored alongside the ciphertext. The v1
/// layout (`nonce || ciphertext`, unsalted BLAKE3 `derive_key`) and the
/// pre-v1 hardcoded-passphrase layout are still *read* for one-time
/// migration but never written.
const MASTER_V2_MAGIC: &[u8; 4] = b"QKM2";
const WRAP_SALT_LEN: usize = 16;

/// Argon2id cost parameters for the master-key wrap (OWASP
/// "interactive" tier: 19 MiB, 2 passes, 1 lane). The derivation runs
/// once per keystore open — process start on Android — so tens of
/// milliseconds is invisible. The passphrase from the Android side is
/// already a full-entropy 256-bit Keystore-wrapped secret, for which
/// stretching adds nothing; the memory-hard KDF + per-install salt are
/// defence-in-depth for every *other* caller of this API (tests,
/// future desktop ports, CLI tools) where nothing enforces passphrase
/// entropy, and they kill cross-install precomputation either way.
const ARGON2_M_COST_KIB: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

/// Secure key storage with encryption and integrity protection.
///
/// Drop behaviour: we use a manual `impl Drop` (further down) that
/// best-effort flushes the keystore to disk. The `master_key` field
/// is wrapped in `SecretBox<[u8; 32]>` which already zeroises on drop,
/// so we don't need `#[derive(ZeroizeOnDrop)]` — combining that
/// derive with the manual impl produced two `Drop` impls and an
/// E0119 conflict.
pub struct SecureKeyStore {
    storage_path: PathBuf,
    /// Data-encryption key: every stored key entry is sealed under
    /// this with ChaCha20-Poly1305. Held only in memory.
    master_key: SecretBox<[u8; 32]>,
    /// Passphrase-derived wrapping key used to seal `master_key` on
    /// disk (`.master` file). Kept so `rotate_master_key` can re-persist
    /// the rotated master key without re-threading the raw passphrase.
    wrap_key: SecretBox<[u8; 32]>,
    /// The per-install random Argon2id salt `wrap_key` was derived
    /// under. Persisted in the `.master` header; kept here so re-seals
    /// (rotation) stay consistent with the stored `wrap_key` without
    /// re-running the KDF.
    wrap_salt: [u8; WRAP_SALT_LEN],
    keys: HashMap<String, EncryptedKeyEntry>,
}

/// Everything `load_master_key` recovers in one pass, so `new()` never
/// runs the (deliberately expensive) KDF twice.
struct UnwrappedMaster {
    master_key: SecretBox<[u8; 32]>,
    wrap_key: SecretBox<[u8; 32]>,
    wrap_salt: [u8; WRAP_SALT_LEN],
}

/// Alias maintained for backwards compatibility with existing code. Some
/// parts of the codebase refer to `SecureKeystore` instead of
/// `SecureKeyStore`. This type alias prevents compilation errors
/// without changing all call sites.
pub type SecureKeystore = SecureKeyStore;

#[derive(Serialize, Deserialize, Clone)]
struct EncryptedKeyEntry {
    encrypted_data: Vec<u8>,
    nonce: [u8; 12],
    key_type: KeyType,
    created_at: u64,
    last_accessed: u64,
    metadata: KeyMetadata,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum KeyType {
    IdentityKey,
    SigningKey,
    EncryptionKey,
    PreKey,
    EphemeralKey,
    RootKey,
    ChainKey,
    MessageKey,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyMetadata {
    pub algorithm: String,
    pub key_size: usize,
    pub usage: Vec<KeyUsage>,
    pub expiry: Option<u64>,
    pub tags: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum KeyUsage {
    Signing,
    Encryption,
    KeyAgreement,
    Authentication,
}

/// Write `data` to `path` atomically: stage it in a sibling `.tmp`
/// file, flush it to disk, then rename over the target. `fs::rename`
/// is atomic on POSIX (Android/Linux), so a crash or power loss leaves
/// either the previous file fully intact or the fully-written new one —
/// never the truncated mix a plain `fs::write` produces, which for the
/// keystore or master-key file would destroy all local key state.
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);

    // Stage the bytes; on any failure remove the temp so a partial
    // `.tmp` can't be left behind (and preserve the original error).
    let staged = (|| -> Result<()> {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("create temp file {}", tmp.display()))?;
        f.write_all(data).context("write temp file")?;
        // Durability: the bytes must hit disk before the rename, or a
        // crash could leave the renamed file pointing at empty content.
        f.sync_all().context("fsync temp file")
    })();
    if staged.is_err() {
        let _ = fs::remove_file(&tmp);
        return staged;
    }

    fs::rename(&tmp, path).context("atomic rename over target")?;

    // The rename is only durable once the containing directory entry is
    // flushed; without this a power loss can resurrect the pre-rename
    // directory state. Best-effort — not all platforms allow fsync on a
    // directory handle, and a failure here doesn't corrupt anything.
    if let Some(dir) = path.parent() {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Domain-separation tag for the per-entry AEAD associated data.
const ENTRY_AAD_TAG: &[u8] = b"qubee_keystore_entry_v1";

/// Stable 1-byte discriminant for [`KeyType`], bound into the entry AAD
/// so a ciphertext can't be relabelled to a different type. Explicit
/// (not `as u8` on the enum) so reordering the enum can't silently
/// change the on-disk binding.
fn key_type_discriminant(kt: &KeyType) -> u8 {
    match kt {
        KeyType::IdentityKey => 0,
        KeyType::SigningKey => 1,
        KeyType::EncryptionKey => 2,
        KeyType::PreKey => 3,
        KeyType::EphemeralKey => 4,
        KeyType::RootKey => 5,
        KeyType::ChainKey => 6,
        KeyType::MessageKey => 7,
    }
}

/// Associated data bound into every entry's ChaCha20-Poly1305: the
/// domain tag, the entry's `key_id`, and its type discriminant. This is
/// what stops an attacker with write access to the `.db` from moving a
/// `(nonce, ciphertext)` pair from one slot to another (e.g. swapping a
/// peer's sender-key state into your own slot) — the AEAD tag no longer
/// verifies once the id/type it's decrypted under differs from the one
/// it was sealed under. `last_accessed` is deliberately *not* bound (it
/// mutates on read); `metadata.tags` is a `HashMap` and excluded to
/// avoid iteration-order nondeterminism.
fn entry_aad(key_id: &str, key_type: &KeyType) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENTRY_AAD_TAG.len() + 2 + key_id.len());
    aad.extend_from_slice(ENTRY_AAD_TAG);
    aad.push(0);
    aad.extend_from_slice(key_id.as_bytes());
    aad.push(0);
    aad.push(key_type_discriminant(key_type));
    aad
}

impl SecureKeyStore {
    /// Create a new secure key store whose master key is wrapped under
    /// the caller-supplied `passphrase`.
    ///
    /// **At-rest security depends entirely on this passphrase.** On
    /// Android it must be a high-entropy secret fetched from the
    /// hardware-backed Keystore (see `SqlCipherKeyProvider`), *not* a
    /// hardcoded value. The previous implementation derived the
    /// wrapping key from a hardcoded `"default_password"`, which made
    /// the on-disk private keys recoverable by anyone with the
    /// `.master` file — that hole is closed by requiring the passphrase
    /// here.
    ///
    /// The wrapping key is derived with **Argon2id** over a
    /// per-install random salt stored in the `.master` header (see
    /// [`ARGON2_M_COST_KIB`] for the parameter rationale). Legacy v1
    /// (unsalted BLAKE3) and pre-v1 (hardcoded passphrase) files are
    /// transparently migrated to the v2 layout on first open.
    pub fn new<P: AsRef<Path>>(storage_path: P, passphrase: &[u8]) -> Result<Self> {
        let storage_path = storage_path.as_ref().to_path_buf();

        // Create storage directory if it doesn't exist
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent).context("Failed to create storage directory")?;
        }

        // Generate or load master key, wrapped under `passphrase`.
        let unwrapped = Self::load_or_generate_master_key(&storage_path, passphrase)?;

        let mut keystore = SecureKeyStore {
            storage_path: storage_path.clone(),
            master_key: unwrapped.master_key,
            wrap_key: unwrapped.wrap_key,
            wrap_salt: unwrapped.wrap_salt,
            keys: HashMap::new(),
        };

        // Load existing keys
        keystore.load_keys()?;

        Ok(keystore)
    }

    /// Store a key in the secure keystore
    pub fn store_key(
        &mut self,
        key_id: &str,
        key_data: &[u8],
        key_type: KeyType,
        metadata: KeyMetadata,
    ) -> Result<()> {
        // Validate key ID
        if key_id.is_empty() || key_id.len() > 256 {
            return Err(anyhow::anyhow!("Invalid key ID"));
        }

        // Generate random nonce
        let nonce_bytes = secure_rng::random::array::<12>()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the key data, binding the entry's id + type as AAD so
        // the ciphertext can't be swapped into a different slot.
        let cipher = ChaCha20Poly1305::new(self.master_key.expose_secret().into());
        let aad = entry_aad(key_id, &key_type);
        let encrypted_data = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: key_data,
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let entry = EncryptedKeyEntry {
            encrypted_data,
            nonce: nonce_bytes,
            key_type,
            created_at: current_time,
            last_accessed: current_time,
            metadata,
        };

        self.keys.insert(key_id.to_string(), entry);
        self.save_keys()?;

        Ok(())
    }

    /// Retrieve a key from the secure keystore
    pub fn retrieve_key(&mut self, key_id: &str) -> Result<Option<SecretBox<Vec<u8>>>> {
        // Snapshot the fields we need without holding a mutable borrow
        // across the possible re-seal + save below.
        let (nonce_bytes, ciphertext, key_type) = match self.keys.get_mut(key_id) {
            Some(entry) => {
                entry.last_accessed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                (
                    entry.nonce,
                    entry.encrypted_data.clone(),
                    entry.key_type.clone(),
                )
            }
            None => return Ok(None),
        };

        let cipher = ChaCha20Poly1305::new(self.master_key.expose_secret().into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = entry_aad(key_id, &key_type);

        // Primary path: decrypt with the entry's bound AAD.
        if let Ok(pt) = cipher.decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        ) {
            return Ok(Some(SecretBox::new(Box::new(pt))));
        }

        // Migration path: entries written before AAD binding sealed with
        // empty AAD. If it opens that way it's a genuine legacy entry —
        // transparently re-seal it *with* AAD (fresh nonce) so the next
        // read is on the hardened path. If it doesn't open either way,
        // it's a wrong key or tampering.
        let legacy_pt = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

        let new_nonce_bytes = secure_rng::random::array::<12>()?;
        let new_ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&new_nonce_bytes),
                Payload {
                    msg: legacy_pt.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow::anyhow!("re-seal on AAD migration: {e}"))?;
        if let Some(entry) = self.keys.get_mut(key_id) {
            entry.encrypted_data = new_ciphertext;
            entry.nonce = new_nonce_bytes;
        }
        self.save_keys()?;

        Ok(Some(SecretBox::new(Box::new(legacy_pt))))
    }

    /// Delete a key from the keystore
    pub fn delete_key(&mut self, key_id: &str) -> Result<bool> {
        let removed = self.keys.remove(key_id).is_some();
        if removed {
            self.save_keys()?;
        }
        Ok(removed)
    }

    /// List all key IDs in the keystore
    pub fn list_keys(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    /// Get key metadata without decrypting the key
    pub fn get_key_metadata(&self, key_id: &str) -> Option<&KeyMetadata> {
        self.keys.get(key_id).map(|entry| &entry.metadata)
    }

    /// Check if a key exists
    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    /// Rotate the master key (re-encrypt all stored keys)
    pub fn rotate_master_key(&mut self) -> Result<()> {
        // Generate new master key
        let new_master_key = SecretBox::new(Box::new(secure_rng::random::array::<32>()?));

        // Re-encrypt all keys with new master key
        let old_cipher = ChaCha20Poly1305::new(self.master_key.expose_secret().into());
        let new_cipher = ChaCha20Poly1305::new(new_master_key.expose_secret().into());

        for (key_id, entry) in self.keys.iter_mut() {
            let aad = entry_aad(key_id, &entry.key_type);
            // Decrypt with old key + the entry's AAD, falling back to the
            // legacy (no-AAD) form for any entry not yet migrated. The
            // plaintext is zeroised the moment the re-encrypt is done
            // (Zeroizing wraps the drop), never left for the allocator.
            let old_nonce = Nonce::from_slice(&entry.nonce);
            let decrypted_data = Zeroizing::new(
                match old_cipher.decrypt(
                    old_nonce,
                    Payload {
                        msg: entry.encrypted_data.as_ref(),
                        aad: &aad,
                    },
                ) {
                    Ok(pt) => pt,
                    Err(_) => old_cipher
                        .decrypt(old_nonce, entry.encrypted_data.as_ref())
                        .map_err(|e| anyhow::anyhow!("Failed to decrypt during rotation: {e}"))?,
                },
            );

            // Generate new nonce and encrypt with new key (AAD bound).
            let new_nonce_bytes = secure_rng::random::array::<12>()?;
            let new_nonce = Nonce::from_slice(&new_nonce_bytes);

            let new_encrypted_data = new_cipher
                .encrypt(
                    new_nonce,
                    Payload {
                        msg: decrypted_data.as_slice(),
                        aad: &aad,
                    },
                )
                .map_err(|e| anyhow::anyhow!("Failed to encrypt during rotation: {e}"))?;

            entry.encrypted_data = new_encrypted_data;
            entry.nonce = new_nonce_bytes;
        }

        // Update master key
        self.master_key = new_master_key;

        // Save updated keystore
        self.save_keys()?;
        self.save_master_key()?;

        Ok(())
    }

    /// Clean up expired keys
    pub fn cleanup_expired_keys(&mut self) -> Result<usize> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let initial_count = self.keys.len();

        self.keys.retain(|_, entry| {
            if let Some(expiry) = entry.metadata.expiry {
                current_time < expiry
            } else {
                true
            }
        });

        let removed_count = initial_count - self.keys.len();

        if removed_count > 0 {
            self.save_keys()?;
        }

        Ok(removed_count)
    }

    fn load_or_generate_master_key(
        storage_path: &Path,
        passphrase: &[u8],
    ) -> Result<UnwrappedMaster> {
        let master_key_path = storage_path.with_extension("master");

        if master_key_path.exists() {
            Self::load_master_key(&master_key_path, passphrase)
        } else {
            let master_key = SecretBox::new(Box::new(secure_rng::random::array::<32>()?));
            Self::rewrap_as_v2(master_key, &master_key_path, passphrase)
        }
    }

    fn load_master_key(path: &Path, passphrase: &[u8]) -> Result<UnwrappedMaster> {
        let encrypted_data = fs::read(path).context("Failed to read master key file")?;

        // v2 layout: "QKM2" || salt(16) || nonce(12) || ciphertext,
        // wrapped under Argon2id(passphrase, salt).
        if encrypted_data.starts_with(MASTER_V2_MAGIC)
            && encrypted_data.len() >= MASTER_V2_MAGIC.len() + WRAP_SALT_LEN + 12
        {
            let mut wrap_salt = [0u8; WRAP_SALT_LEN];
            wrap_salt.copy_from_slice(
                &encrypted_data[MASTER_V2_MAGIC.len()..MASTER_V2_MAGIC.len() + WRAP_SALT_LEN],
            );
            let body = &encrypted_data[MASTER_V2_MAGIC.len() + WRAP_SALT_LEN..];
            let wrap_key = Self::derive_wrap_key_v2(passphrase, &wrap_salt)?;
            if let Ok(master_key) = Self::try_decrypt_master(body, wrap_key.expose_secret()) {
                return Ok(UnwrappedMaster {
                    master_key,
                    wrap_key,
                    wrap_salt,
                });
            }
            // A genuine v2 file failing here means a wrong passphrase;
            // fall through anyway so a (2^-32) v1 file whose nonce
            // happens to start with the magic still opens.
        }

        if encrypted_data.len() >= 12 {
            // v1 migration: `nonce || ciphertext`, wrapped under the
            // unsalted BLAKE3 derivation of the real passphrase.
            let derived = Self::derive_key_v1(passphrase);
            if let Ok(master_key) = Self::try_decrypt_master(&encrypted_data, &derived) {
                return Self::rewrap_as_v2(master_key, path, passphrase);
            }

            // Pre-v1 migration: same layout, but wrapped under the
            // hardcoded legacy passphrase (a *different* derivation
            // construction). If it unwraps, transparently re-wrap
            // under the real passphrase + v2 layout. Non-destructive —
            // existing identity material is preserved.
            let legacy = Self::derive_key_legacy();
            if let Ok(master_key) = Self::try_decrypt_master(&encrypted_data, &legacy) {
                return Self::rewrap_as_v2(master_key, path, passphrase);
            }
        }

        Err(anyhow::anyhow!(
            "Failed to decrypt master key (wrong passphrase or corrupt file)"
        ))
    }

    /// Seal `master_key` to `path` in the v2 layout under a **fresh**
    /// random salt, returning the full unwrapped state. Used for new
    /// keystores and for migrating v1 / legacy files.
    fn rewrap_as_v2(
        master_key: SecretBox<[u8; 32]>,
        path: &Path,
        passphrase: &[u8],
    ) -> Result<UnwrappedMaster> {
        let wrap_salt: [u8; WRAP_SALT_LEN] = secure_rng::random::array::<WRAP_SALT_LEN>()?;
        let wrap_key = Self::derive_wrap_key_v2(passphrase, &wrap_salt)?;
        Self::seal_master_v2(&master_key, path, wrap_key.expose_secret(), &wrap_salt)?;
        Ok(UnwrappedMaster {
            master_key,
            wrap_key,
            wrap_salt,
        })
    }

    /// Attempt to unwrap the master-key file with an already-derived
    /// 32-byte wrapping key. Returns `Err` on AEAD failure (wrong key
    /// / tampering) so callers can try a fallback.
    fn try_decrypt_master(
        encrypted_data: &[u8],
        derived_key: &[u8; 32],
    ) -> Result<SecretBox<[u8; 32]>> {
        let cipher = ChaCha20Poly1305::new_from_slice(derived_key).expect("32-byte key");
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];

        let mut decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt master key: {e}"))?;

        if decrypted.len() != 32 {
            decrypted.zeroize();
            return Err(anyhow::anyhow!("Invalid master key size"));
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&decrypted);
        decrypted.zeroize();
        Ok(SecretBox::new(Box::new(key_array)))
    }

    /// Re-persist the in-memory `master_key` to disk, sealed under the
    /// stored `wrap_key` + `wrap_salt` (no KDF re-run). Used after
    /// rotation.
    fn save_master_key(&self) -> Result<()> {
        let master_key_path = self.storage_path.with_extension("master");
        Self::seal_master_v2(
            &self.master_key,
            &master_key_path,
            self.wrap_key.expose_secret(),
            &self.wrap_salt,
        )
    }

    /// Write the v2 `.master` layout:
    /// `"QKM2" || salt(16) || nonce(12) || ciphertext`. The salt is
    /// stored in the clear alongside the ciphertext — it isn't a
    /// secret, it exists so the Argon2id derivation is unique per
    /// install.
    fn seal_master_v2(
        master_key: &SecretBox<[u8; 32]>,
        path: &Path,
        wrap_key: &[u8; 32],
        salt: &[u8; WRAP_SALT_LEN],
    ) -> Result<()> {
        let cipher = ChaCha20Poly1305::new_from_slice(wrap_key).expect("32-byte key");
        let nonce_bytes = secure_rng::random::array::<12>()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, master_key.expose_secret().as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt master key: {e}"))?;

        let mut file_data =
            Vec::with_capacity(MASTER_V2_MAGIC.len() + WRAP_SALT_LEN + 12 + encrypted.len());
        file_data.extend_from_slice(MASTER_V2_MAGIC);
        file_data.extend_from_slice(salt);
        file_data.extend_from_slice(&nonce_bytes);
        file_data.extend_from_slice(&encrypted);

        atomic_write(path, &file_data).context("Failed to write master key file")?;

        Ok(())
    }

    /// v1-layout writer (`nonce || ciphertext`, no salt). Retained only
    /// so tests can forge pre-migration files.
    #[cfg(test)]
    fn seal_master_key_to_path(
        master_key: &SecretBox<[u8; 32]>,
        path: &Path,
        wrap_key: &[u8; 32],
    ) -> Result<()> {
        let cipher = ChaCha20Poly1305::new_from_slice(wrap_key).expect("32-byte key");
        let nonce_bytes = secure_rng::random::array::<12>()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, master_key.expose_secret().as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt master key: {e}"))?;
        let mut file_data = Vec::with_capacity(12 + encrypted.len());
        file_data.extend_from_slice(&nonce_bytes);
        file_data.extend_from_slice(&encrypted);
        fs::write(path, file_data).context("Failed to write master key file")?;
        Ok(())
    }

    /// Derive the master-key-wrapping key: **Argon2id** over the
    /// per-install salt from the `.master` header. See
    /// [`ARGON2_M_COST_KIB`] for the parameter rationale.
    fn derive_wrap_key_v2(
        passphrase: &[u8],
        salt: &[u8; WRAP_SALT_LEN],
    ) -> Result<SecretBox<[u8; 32]>> {
        let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| anyhow::anyhow!("Argon2 params: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow::anyhow!("Argon2 derivation: {e}"))?;
        let boxed = SecretBox::new(Box::new(out));
        out.zeroize();
        Ok(boxed)
    }

    /// The v1 derivation (unsalted BLAKE3 `derive_key`), kept only so
    /// the migration path in [`load_master_key`] can unwrap a v1
    /// `.master` file. Never used for writing.
    fn derive_key_v1(passphrase: &[u8]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(blake3::derive_key(
            "qubee secure_keystore master-wrap v1",
            passphrase,
        ))
    }

    /// Reproduce the *exact* pre-this-change derivation
    /// (`BLAKE3("default_password" || "qubee_keystore_salt")[..32]`) so
    /// the migration path in [`load_master_key`] can unwrap a legacy
    /// `.master` file. Used only for one-time migration; never for
    /// writing. Once a legacy file is re-wrapped under the real
    /// passphrase this code path is never hit again for that install.
    fn derive_key_legacy() -> Zeroizing<[u8; 32]> {
        let mut hasher = Hasher::new();
        hasher.update(b"default_password");
        hasher.update(b"qubee_keystore_salt");
        let hash = hasher.finalize();
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&hash.as_bytes()[..32]);
        key
    }

    fn load_keys(&mut self) -> Result<()> {
        if !self.storage_path.exists() {
            return Ok(());
        }

        let data = fs::read(&self.storage_path).context("Failed to read keystore file")?;

        if data.is_empty() {
            return Ok(());
        }

        self.keys = bincode::deserialize(&data).context("Failed to deserialize keystore")?;

        Ok(())
    }

    fn save_keys(&self) -> Result<()> {
        let data = bincode::serialize(&self.keys).context("Failed to serialize keystore")?;

        atomic_write(&self.storage_path, &data).context("Failed to write keystore file")?;

        Ok(())
    }
}

impl Drop for SecureKeyStore {
    fn drop(&mut self) {
        // Attempt to save keys on drop
        let _ = self.save_keys();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_keystore() -> (SecureKeyStore, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keystore_path = temp_dir.path().join("test_keystore.db");
        let keystore = SecureKeyStore::new(keystore_path, b"test-keystore-passphrase")
            .expect("Failed to create keystore");
        (keystore, temp_dir)
    }

    #[test]
    fn wrong_passphrase_cannot_open_keystore() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("ks.db");

        // Create + store a key under passphrase A.
        {
            let mut ks = SecureKeyStore::new(&path, b"passphrase-A").unwrap();
            ks.store_key(
                "k",
                b"super secret key material 0123456789",
                KeyType::IdentityKey,
                KeyMetadata {
                    algorithm: "x".into(),
                    key_size: 36,
                    usage: vec![KeyUsage::Signing],
                    expiry: None,
                    tags: HashMap::new(),
                },
            )
            .unwrap();
        }

        // Opening with a different passphrase must fail — the on-disk
        // master key won't unwrap. This is the property that makes the
        // at-rest encryption real: without the Keystore-derived
        // passphrase the private keys are unrecoverable.
        let reopened = SecureKeyStore::new(&path, b"passphrase-B");
        assert!(
            reopened.is_err(),
            "keystore opened under the wrong passphrase — at-rest encryption is broken",
        );

        // Sanity: the correct passphrase still opens it.
        let ok = SecureKeyStore::new(&path, b"passphrase-A");
        assert!(ok.is_ok(), "correct passphrase must still open");
    }

    #[test]
    fn legacy_master_key_migrates_to_real_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("ks.db");
        let master_path = path.with_extension("master");

        // Forge a legacy `.master` file: a random master key wrapped
        // under the old hardcoded `default_password` derivation, exactly
        // as the pre-this-change build would have written it.
        let legacy_master = SecretBox::new(Box::new(secure_rng::random::array::<32>().unwrap()));
        let legacy_wrap = SecureKeyStore::derive_key_legacy();
        SecureKeyStore::seal_master_key_to_path(&legacy_master, &master_path, &legacy_wrap)
            .unwrap();

        // Also store a key entry sealed under that legacy master key so
        // we can prove the migration preserves real data.
        {
            let cipher = ChaCha20Poly1305::new(legacy_master.expose_secret().into());
            let nonce_bytes = secure_rng::random::array::<12>().unwrap();
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ct = cipher
                .encrypt(nonce, b"legacy identity key".as_ref())
                .unwrap();
            let mut keys = HashMap::new();
            keys.insert(
                "id".to_string(),
                EncryptedKeyEntry {
                    encrypted_data: ct,
                    nonce: nonce_bytes,
                    key_type: KeyType::IdentityKey,
                    created_at: 0,
                    last_accessed: 0,
                    metadata: KeyMetadata {
                        algorithm: "x".into(),
                        key_size: 19,
                        usage: vec![],
                        expiry: None,
                        tags: HashMap::new(),
                    },
                },
            );
            fs::write(&path, bincode::serialize(&keys).unwrap()).unwrap();
        }

        // Open under the REAL passphrase. The migration path detects the
        // legacy wrapping, re-wraps under the real passphrase, and the
        // stored key is still retrievable.
        let mut ks = SecureKeyStore::new(&path, b"real-keystore-passphrase").unwrap();
        let got = ks
            .retrieve_key("id")
            .unwrap()
            .expect("legacy key survived migration");
        assert_eq!(got.expose_secret().as_slice(), b"legacy identity key");

        // After migration the `.master` is re-wrapped: opening with the
        // legacy passphrase derivation must NO LONGER work, and the real
        // passphrase must.
        drop(ks);
        let legacy_reopen = {
            let data = fs::read(&master_path).unwrap();
            SecureKeyStore::try_decrypt_master(&data, &SecureKeyStore::derive_key_legacy())
        };
        assert!(
            legacy_reopen.is_err(),
            "after migration the master key must no longer unwrap under the legacy key",
        );
        assert!(SecureKeyStore::new(&path, b"real-keystore-passphrase").is_ok());
    }

    #[test]
    fn test_store_and_retrieve_key() {
        let (mut keystore, _temp_dir) = create_test_keystore();

        let key_data = b"test_key_data_12345678901234567890";
        let metadata = KeyMetadata {
            algorithm: "ChaCha20Poly1305".to_string(),
            key_size: 32,
            usage: vec![KeyUsage::Encryption],
            expiry: None,
            tags: HashMap::new(),
        };

        // Store key
        keystore
            .store_key("test_key", key_data, KeyType::EncryptionKey, metadata)
            .expect("Failed to store key");

        // Retrieve key
        let retrieved = keystore
            .retrieve_key("test_key")
            .expect("Failed to retrieve key")
            .expect("Key not found");

        assert_eq!(retrieved.expose_secret(), key_data);
    }

    #[test]
    fn test_key_not_found() {
        let (mut keystore, _temp_dir) = create_test_keystore();

        let result = keystore
            .retrieve_key("nonexistent_key")
            .expect("Should not error");
        assert!(result.is_none());
    }

    #[test]
    fn test_delete_key() {
        let (mut keystore, _temp_dir) = create_test_keystore();

        let key_data = b"test_key_data";
        let metadata = KeyMetadata {
            algorithm: "Test".to_string(),
            key_size: 13,
            usage: vec![KeyUsage::Signing],
            expiry: None,
            tags: HashMap::new(),
        };

        keystore
            .store_key("test_key", key_data, KeyType::SigningKey, metadata)
            .expect("Failed to store key");

        assert!(keystore.has_key("test_key"));

        let deleted = keystore
            .delete_key("test_key")
            .expect("Failed to delete key");
        assert!(deleted);
        assert!(!keystore.has_key("test_key"));
    }

    #[test]
    fn test_list_keys() {
        let (mut keystore, _temp_dir) = create_test_keystore();

        let metadata = KeyMetadata {
            algorithm: "Test".to_string(),
            key_size: 32,
            usage: vec![KeyUsage::Encryption],
            expiry: None,
            tags: HashMap::new(),
        };

        keystore
            .store_key("key1", b"data1", KeyType::EncryptionKey, metadata.clone())
            .expect("Failed to store key1");

        keystore
            .store_key("key2", b"data2", KeyType::SigningKey, metadata)
            .expect("Failed to store key2");

        let keys = keystore.list_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
    }

    #[test]
    fn test_master_key_rotation() {
        let (mut keystore, _temp_dir) = create_test_keystore();

        let key_data = b"test_key_data_for_rotation";
        let metadata = KeyMetadata {
            algorithm: "Test".to_string(),
            key_size: 26,
            usage: vec![KeyUsage::Encryption],
            expiry: None,
            tags: HashMap::new(),
        };

        // Store a key
        keystore
            .store_key("test_key", key_data, KeyType::EncryptionKey, metadata)
            .expect("Failed to store key");

        // Rotate master key
        keystore
            .rotate_master_key()
            .expect("Failed to rotate master key");

        // Verify key can still be retrieved
        let retrieved = keystore
            .retrieve_key("test_key")
            .expect("Failed to retrieve key after rotation")
            .expect("Key not found after rotation");

        assert_eq!(retrieved.expose_secret(), key_data);
    }

    fn plain_metadata(size: usize) -> KeyMetadata {
        KeyMetadata {
            algorithm: "x".into(),
            key_size: size,
            usage: vec![KeyUsage::Encryption],
            expiry: None,
            tags: HashMap::new(),
        }
    }

    #[test]
    fn writes_are_atomic_and_leave_no_partial_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ks.db");
        let mut ks = SecureKeyStore::new(&path, b"atomic-pass").unwrap();

        // Many store/rotate cycles; each must leave a fully-valid db and
        // .master (rename-over-target), never a truncated temp.
        for i in 0..8 {
            ks.store_key(
                &format!("k{i}"),
                format!("val{i}").as_bytes(),
                KeyType::EncryptionKey,
                plain_metadata(4),
            )
            .unwrap();
        }
        ks.rotate_master_key().unwrap();
        drop(ks);

        // No leftover temp files, and everything reopens + reads back.
        assert!(!path.with_extension("db.tmp").exists());
        assert!(!dir.path().join("ks.master.tmp").exists());
        let mut ks = SecureKeyStore::new(&path, b"atomic-pass").unwrap();
        for i in 0..8 {
            assert_eq!(
                ks.retrieve_key(&format!("k{i}"))
                    .unwrap()
                    .unwrap()
                    .expose_secret(),
                format!("val{i}").as_bytes(),
            );
        }
    }

    #[test]
    fn entry_ciphertext_cannot_be_swapped_between_slots() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ks.db");
        let mut ks = SecureKeyStore::new(&path, b"aad-swap-pass").unwrap();
        ks.store_key(
            "slot_a",
            b"alice secret",
            KeyType::RootKey,
            plain_metadata(12),
        )
        .unwrap();
        ks.store_key(
            "slot_b",
            b"bob secret",
            KeyType::RootKey,
            plain_metadata(10),
        )
        .unwrap();
        drop(ks);

        // Attacker with .db write access moves slot_a's sealed bytes into
        // slot_b (same master key, so without AAD this would decrypt).
        let mut keys: HashMap<String, EncryptedKeyEntry> =
            bincode::deserialize(&fs::read(&path).unwrap()).unwrap();
        let a = keys.get("slot_a").unwrap().clone();
        let b = keys.get_mut("slot_b").unwrap();
        b.encrypted_data = a.encrypted_data.clone();
        b.nonce = a.nonce;
        fs::write(&path, bincode::serialize(&keys).unwrap()).unwrap();

        // The AAD (key_id "slot_b") no longer matches what was sealed
        // under "slot_a", so the swapped entry must fail to open.
        let mut ks = SecureKeyStore::new(&path, b"aad-swap-pass").unwrap();
        assert!(
            ks.retrieve_key("slot_b").is_err(),
            "AAD must reject a ciphertext moved from a different slot",
        );
        // The untouched slot still opens.
        assert_eq!(
            ks.retrieve_key("slot_a").unwrap().unwrap().expose_secret(),
            b"alice secret",
        );
    }

    #[test]
    fn entry_type_cannot_be_relabelled() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ks.db");
        let mut ks = SecureKeyStore::new(&path, b"aad-type-pass").unwrap();
        ks.store_key(
            "k",
            b"typed secret",
            KeyType::SigningKey,
            plain_metadata(12),
        )
        .unwrap();
        drop(ks);

        // Flip the stored key_type; the AAD binds the type discriminant.
        let mut keys: HashMap<String, EncryptedKeyEntry> =
            bincode::deserialize(&fs::read(&path).unwrap()).unwrap();
        keys.get_mut("k").unwrap().key_type = KeyType::EncryptionKey;
        fs::write(&path, bincode::serialize(&keys).unwrap()).unwrap();

        let mut ks = SecureKeyStore::new(&path, b"aad-type-pass").unwrap();
        assert!(
            ks.retrieve_key("k").is_err(),
            "relabelling the key type must invalidate the AEAD tag",
        );
    }

    #[test]
    fn legacy_no_aad_entry_opens_and_migrates() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ks.db");
        // Forge a pre-AAD entry: seal with empty AAD directly under a
        // master key, exactly as an older build wrote it.
        let mut ks = SecureKeyStore::new(&path, b"legacy-aad-pass").unwrap();
        let master = ks.master_key.expose_secret();
        let cipher = ChaCha20Poly1305::new(master.into());
        let nonce_bytes = secure_rng::random::array::<12>().unwrap();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), b"legacy value".as_ref())
            .unwrap();
        ks.keys.insert(
            "legacy".to_string(),
            EncryptedKeyEntry {
                encrypted_data: ct,
                nonce: nonce_bytes,
                key_type: KeyType::EncryptionKey,
                created_at: 0,
                last_accessed: 0,
                metadata: plain_metadata(12),
            },
        );
        ks.save_keys().unwrap();

        // First read opens it (empty-AAD fallback) and re-seals with AAD.
        assert_eq!(
            ks.retrieve_key("legacy").unwrap().unwrap().expose_secret(),
            b"legacy value",
        );
        drop(ks);

        // Reopen: the migrated entry now opens on the primary AAD path,
        // and its bytes are no longer the empty-AAD form (verify a raw
        // empty-AAD decrypt of the stored ciphertext now fails).
        let mut ks = SecureKeyStore::new(&path, b"legacy-aad-pass").unwrap();
        assert_eq!(
            ks.retrieve_key("legacy").unwrap().unwrap().expose_secret(),
            b"legacy value",
        );
        let migrated = ks.keys.get("legacy").unwrap();
        let cipher = ChaCha20Poly1305::new(ks.master_key.expose_secret().into());
        assert!(
            cipher
                .decrypt(
                    Nonce::from_slice(&migrated.nonce),
                    migrated.encrypted_data.as_ref()
                )
                .is_err(),
            "after migration the entry must no longer open under empty AAD",
        );
    }

    #[test]
    fn master_file_uses_v2_layout_with_per_install_salt() {
        let (d1, d2) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let (p1, p2) = (d1.path().join("ks.db"), d2.path().join("ks.db"));
        // Same passphrase on two installs.
        SecureKeyStore::new(&p1, b"same-passphrase").unwrap();
        SecureKeyStore::new(&p2, b"same-passphrase").unwrap();

        let f1 = fs::read(p1.with_extension("master")).unwrap();
        let f2 = fs::read(p2.with_extension("master")).unwrap();
        assert!(f1.starts_with(MASTER_V2_MAGIC));
        assert!(f2.starts_with(MASTER_V2_MAGIC));

        let salt =
            |f: &[u8]| f[MASTER_V2_MAGIC.len()..MASTER_V2_MAGIC.len() + WRAP_SALT_LEN].to_vec();
        assert_ne!(
            salt(&f1),
            salt(&f2),
            "two installs with the same passphrase must get different salts",
        );
    }

    #[test]
    fn v1_master_file_migrates_to_v2_and_preserves_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ks.db");
        let master_path = path.with_extension("master");
        let passphrase = b"v1-era-passphrase";

        // Forge a v1-era install: master key wrapped under the unsalted
        // BLAKE3 derivation, one entry sealed under that master key.
        let master = SecretBox::new(Box::new(secure_rng::random::array::<32>().unwrap()));
        let v1_wrap = SecureKeyStore::derive_key_v1(passphrase);
        SecureKeyStore::seal_master_key_to_path(&master, &master_path, &v1_wrap).unwrap();
        {
            let cipher = ChaCha20Poly1305::new(master.expose_secret().into());
            let nonce_bytes = secure_rng::random::array::<12>().unwrap();
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), b"v1 identity key".as_ref())
                .unwrap();
            let mut keys = HashMap::new();
            keys.insert(
                "id".to_string(),
                EncryptedKeyEntry {
                    encrypted_data: ct,
                    nonce: nonce_bytes,
                    key_type: KeyType::IdentityKey,
                    created_at: 0,
                    last_accessed: 0,
                    metadata: plain_metadata(15),
                },
            );
            fs::write(&path, bincode::serialize(&keys).unwrap()).unwrap();
        }

        // Opening under the same passphrase migrates the wrap to v2 and
        // keeps the data readable.
        let mut ks = SecureKeyStore::new(&path, passphrase).unwrap();
        let got = ks.retrieve_key("id").unwrap().expect("v1 key survived");
        assert_eq!(got.expose_secret().as_slice(), b"v1 identity key");
        drop(ks);

        let migrated = fs::read(&master_path).unwrap();
        assert!(
            migrated.starts_with(MASTER_V2_MAGIC),
            "migration must land the .master file on the v2 layout",
        );
        // And it still opens (Argon2id path) while a wrong passphrase fails.
        assert!(SecureKeyStore::new(&path, passphrase).is_ok());
        assert!(SecureKeyStore::new(&path, b"wrong").is_err());
    }

    #[test]
    fn rotation_reseals_under_stored_salt_and_reopens() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ks.db");
        let passphrase = b"rotation-passphrase";

        let mut ks = SecureKeyStore::new(&path, passphrase).unwrap();
        ks.store_key(
            "k",
            b"data before rotation",
            KeyType::EncryptionKey,
            plain_metadata(20),
        )
        .unwrap();
        ks.rotate_master_key().unwrap();
        drop(ks);

        // The re-sealed .master must still be v2 and re-derivable from
        // the salt stored in its own header.
        assert!(fs::read(path.with_extension("master"))
            .unwrap()
            .starts_with(MASTER_V2_MAGIC));
        let mut reopened = SecureKeyStore::new(&path, passphrase).unwrap();
        assert_eq!(
            reopened
                .retrieve_key("k")
                .unwrap()
                .unwrap()
                .expose_secret()
                .as_slice(),
            b"data before rotation",
        );
    }
}
