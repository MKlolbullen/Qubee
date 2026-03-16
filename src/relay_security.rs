use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayPublicBundleEntry {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "identityFingerprint")]
    pub identity_fingerprint: String,
    #[serde(rename = "publicBundleBase64")]
    pub public_bundle_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingRelinkRequest {
    #[serde(rename = "relinkToken")]
    pub relink_token: String,
    pub handle: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "existingIdentityFingerprint")]
    pub existing_identity_fingerprint: String,
    #[serde(rename = "requestedIdentityFingerprint")]
    pub requested_identity_fingerprint: String,
    #[serde(rename = "publicBundleBase64")]
    pub public_bundle_base64: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingDecision {
    NewBinding,
    ExistingBinding,
    Conflict {
        relink_token: String,
        existing_identity_fingerprint: String,
        requested_identity_fingerprint: String,
    },
}

#[derive(Debug, Default, Clone)]
pub struct HandleBindingRegistry {
    bindings: HashMap<(String, String), RelayPublicBundleEntry>,
    pending_relinks: HashMap<String, PendingRelinkRequest>,
}

impl HandleBindingRegistry {
    pub fn validate_or_bind(
        &mut self,
        handle: &str,
        device_id: &str,
        identity_fingerprint: &str,
        public_bundle_base64: &str,
    ) -> Result<BindingDecision> {
        let key = (handle.to_string(), device_id.to_string());
        let candidate = RelayPublicBundleEntry {
            device_id: device_id.to_string(),
            identity_fingerprint: identity_fingerprint.to_string(),
            public_bundle_base64: public_bundle_base64.to_string(),
        };

        // Pre-collect data from immutable borrow before any mutable operations.
        let existing_state = self.bindings.get(&key).map(|existing| {
            let matches = existing.identity_fingerprint == candidate.identity_fingerprint
                && existing.public_bundle_base64 == candidate.public_bundle_base64;
            (matches, existing.identity_fingerprint.clone())
        });

        match existing_state {
            Some((true, _)) => Ok(BindingDecision::ExistingBinding),
            Some((false, existing_fp)) => {
                let relink_token = self.register_pending_relink(
                    handle,
                    device_id,
                    &existing_fp,
                    identity_fingerprint,
                    public_bundle_base64,
                );
                Ok(BindingDecision::Conflict {
                    relink_token,
                    existing_identity_fingerprint: existing_fp,
                    requested_identity_fingerprint: identity_fingerprint.to_string(),
                })
            }
            None => {
                self.bindings.insert(key, candidate);
                Ok(BindingDecision::NewBinding)
            }
        }
    }

    pub fn rotate_binding(
        &mut self,
        handle: &str,
        device_id: &str,
        current_identity_fingerprint: &str,
        new_identity_fingerprint: &str,
        new_public_bundle_base64: &str,
    ) -> Result<RelayPublicBundleEntry> {
        let key = (handle.to_string(), device_id.to_string());
        let existing = self
            .bindings
            .get(&key)
            .ok_or_else(|| anyhow!("no existing binding for handle/device"))?;

        if existing.identity_fingerprint != current_identity_fingerprint {
            return Err(anyhow!("rotation fingerprint mismatch for existing binding"));
        }
        if existing.identity_fingerprint == new_identity_fingerprint
            && existing.public_bundle_base64 == new_public_bundle_base64
        {
            return Ok(existing.clone());
        }

        let replacement = RelayPublicBundleEntry {
            device_id: device_id.to_string(),
            identity_fingerprint: new_identity_fingerprint.to_string(),
            public_bundle_base64: new_public_bundle_base64.to_string(),
        };
        self.bindings.insert(key, replacement.clone());
        self.pending_relinks.retain(|_, pending| {
            !(pending.handle == handle && pending.device_id == device_id)
        });
        Ok(replacement)
    }

    pub fn approve_device_relink(
        &mut self,
        approver_handle: &str,
        handle: &str,
        device_id: &str,
        relink_token: &str,
    ) -> Result<RelayPublicBundleEntry> {
        if approver_handle != handle {
            return Err(anyhow!("approver must belong to the same handle"));
        }

        let pending = self
            .pending_relinks
            .remove(relink_token)
            .ok_or_else(|| anyhow!("unknown relink token"))?;

        if pending.handle != handle || pending.device_id != device_id {
            return Err(anyhow!("relink token does not match handle/device"));
        }

        let replacement = RelayPublicBundleEntry {
            device_id: pending.device_id.clone(),
            identity_fingerprint: pending.requested_identity_fingerprint.clone(),
            public_bundle_base64: pending.public_bundle_base64.clone(),
        };
        self.bindings
            .insert((pending.handle.clone(), pending.device_id.clone()), replacement.clone());
        Ok(replacement)
    }

    pub fn pending_relink(&self, relink_token: &str) -> Option<PendingRelinkRequest> {
        self.pending_relinks.get(relink_token).cloned()
    }

    pub fn bindings_for_handle(
        &self,
        handle: &str,
        requested_device_id: Option<&str>,
    ) -> Vec<RelayPublicBundleEntry> {
        let mut entries = self
            .bindings
            .iter()
            .filter(|((entry_handle, entry_device), _)| {
                entry_handle == handle
                    && requested_device_id
                        .map(|requested| requested == entry_device)
                        .unwrap_or(true)
            })
            .map(|(_, entry)| entry.clone())
            .collect::<Vec<_>>();

        entries.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        entries
    }

    pub fn remove_binding(&mut self, handle: &str, device_id: &str) {
        self.bindings.remove(&(handle.to_string(), device_id.to_string()));
        self.pending_relinks.retain(|_, pending| {
            !(pending.handle == handle && pending.device_id == device_id)
        });
    }

    fn register_pending_relink(
        &mut self,
        handle: &str,
        device_id: &str,
        existing_identity_fingerprint: &str,
        requested_identity_fingerprint: &str,
        public_bundle_base64: &str,
    ) -> String {
        if let Some((token, _)) = self.pending_relinks.iter().find(|(_, pending)| {
            pending.handle == handle
                && pending.device_id == device_id
                && pending.existing_identity_fingerprint == existing_identity_fingerprint
                && pending.requested_identity_fingerprint == requested_identity_fingerprint
                && pending.public_bundle_base64 == public_bundle_base64
        }) {
            return token.clone();
        }

        let token = format!("relink-{}", Uuid::new_v4());
        self.pending_relinks.insert(
            token.clone(),
            PendingRelinkRequest {
                relink_token: token.clone(),
                handle: handle.to_string(),
                device_id: device_id.to_string(),
                existing_identity_fingerprint: existing_identity_fingerprint.to_string(),
                requested_identity_fingerprint: requested_identity_fingerprint.to_string(),
                public_bundle_base64: public_bundle_base64.to_string(),
                created_at: now_ms(),
            },
        );
        token
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitDecision {
    Allowed,
    Denied { retry_after_ms: u64 },
}

#[derive(Debug, Clone, Default)]
struct RateLimitBucket {
    tokens: f64,
    last_refill_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RateLimitRegistry {
    capacity: f64,
    refill_per_second: f64,
    buckets: HashMap<String, RateLimitBucket>,
}

impl RateLimitRegistry {
    pub fn new(capacity: u32, refill_per_second: u32) -> Self {
        Self {
            capacity: capacity as f64,
            refill_per_second: refill_per_second as f64,
            buckets: HashMap::new(),
        }
    }

    pub fn check(&mut self, key: &str, cost: u32) -> RateLimitDecision {
        self.check_at(key, cost, now_ms())
    }

    pub fn check_at(&mut self, key: &str, cost: u32, now_ms: u64) -> RateLimitDecision {
        let cost = cost as f64;
        let bucket = self.buckets.entry(key.to_string()).or_insert_with(|| RateLimitBucket {
            tokens: self.capacity,
            last_refill_ms: now_ms,
        });
        let elapsed_ms = now_ms.saturating_sub(bucket.last_refill_ms);
        if elapsed_ms > 0 {
            let refill = (elapsed_ms as f64 / 1000.0) * self.refill_per_second;
            bucket.tokens = (bucket.tokens + refill).min(self.capacity);
            bucket.last_refill_ms = now_ms;
        }
        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            return RateLimitDecision::Allowed;
        }
        let missing = (cost - bucket.tokens).max(0.0);
        let retry_after_ms = ((missing / self.refill_per_second) * 1000.0).ceil() as u64;
        RateLimitDecision::Denied { retry_after_ms: retry_after_ms.max(1) }
    }

    pub fn purge_stale(&mut self, older_than_ms: u64) {
        let cutoff = now_ms().saturating_sub(older_than_ms);
        self.buckets.retain(|_, bucket| bucket.last_refill_ms >= cutoff);
    }
}


#[cfg(test)]
mod tests {
    use super::{BindingDecision, HandleBindingRegistry, RateLimitDecision, RateLimitRegistry};

    #[test]
    fn accepts_repeat_binding_with_same_material() {
        let mut registry = HandleBindingRegistry::default();
        let first = registry
            .validate_or_bind("alice", "pixel", "fp-1", "bundle-1")
            .expect("first bind should succeed");
        let second = registry
            .validate_or_bind("alice", "pixel", "fp-1", "bundle-1")
            .expect("repeat bind should succeed");

        assert_eq!(first, BindingDecision::NewBinding);
        assert_eq!(second, BindingDecision::ExistingBinding);
    }

    #[test]
    fn conflicting_binding_creates_pending_relink_instead_of_hard_error() {
        let mut registry = HandleBindingRegistry::default();
        registry
            .validate_or_bind("alice", "pixel", "fp-1", "bundle-1")
            .expect("initial bind should succeed");

        let decision = registry
            .validate_or_bind("alice", "pixel", "fp-2", "bundle-2")
            .expect("conflicting bind should produce a decision");

        match decision {
            BindingDecision::Conflict {
                relink_token,
                existing_identity_fingerprint,
                requested_identity_fingerprint,
            } => {
                assert_eq!(existing_identity_fingerprint, "fp-1");
                assert_eq!(requested_identity_fingerprint, "fp-2");
                let pending = registry.pending_relink(&relink_token).expect("pending relink should exist");
                assert_eq!(pending.handle, "alice");
                assert_eq!(pending.device_id, "pixel");
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn approving_relink_replaces_binding() {
        let mut registry = HandleBindingRegistry::default();
        registry
            .validate_or_bind("alice", "pixel", "fp-1", "bundle-1")
            .expect("initial bind should succeed");

        let relink_token = match registry
            .validate_or_bind("alice", "pixel", "fp-2", "bundle-2")
            .expect("conflict should produce pending relink")
        {
            BindingDecision::Conflict { relink_token, .. } => relink_token,
            other => panic!("unexpected decision: {other:?}"),
        };

        let updated = registry
            .approve_device_relink("alice", "alice", "pixel", &relink_token)
            .expect("approval should succeed");

        assert_eq!(updated.identity_fingerprint, "fp-2");
        assert_eq!(updated.public_bundle_base64, "bundle-2");
        assert!(registry.pending_relink(&relink_token).is_none());
    }

    #[test]
    fn rotating_existing_binding_updates_fingerprint_without_pending_relink() {
        let mut registry = HandleBindingRegistry::default();
        registry
            .validate_or_bind("alice", "phone", "fp-1", "bundle-1")
            .expect("phone bind should succeed");

        let updated = registry
            .rotate_binding("alice", "phone", "fp-1", "fp-2", "bundle-2")
            .expect("rotation should succeed");

        assert_eq!(updated.identity_fingerprint, "fp-2");
        let all = registry.bindings_for_handle("alice", Some("phone"));
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].public_bundle_base64, "bundle-2");
    }

    #[test]
    fn returns_device_specific_bundle_selection_deterministically() {
        let mut registry = HandleBindingRegistry::default();
        registry
            .validate_or_bind("alice", "tablet", "fp-2", "bundle-2")
            .expect("tablet bind should succeed");
        registry
            .validate_or_bind("alice", "phone", "fp-1", "bundle-1")
            .expect("phone bind should succeed");

        let all = registry.bindings_for_handle("alice", None);
        let phone = registry.bindings_for_handle("alice", Some("phone"));

        assert_eq!(all.len(), 2);
        assert_eq!(all[0].device_id, "phone");
        assert_eq!(all[1].device_id, "tablet");
        assert_eq!(phone.len(), 1);
        assert_eq!(phone[0].public_bundle_base64, "bundle-1");
    }
}


#[cfg(test)]
mod rate_limit_tests {
    use super::{RateLimitDecision, RateLimitRegistry};

    #[test]
    fn allows_burst_then_blocks_until_refill() {
        let mut limiter = RateLimitRegistry::new(2, 1);
        assert_eq!(limiter.check_at("alice", 1, 0), RateLimitDecision::Allowed);
        assert_eq!(limiter.check_at("alice", 1, 0), RateLimitDecision::Allowed);
        match limiter.check_at("alice", 1, 0) {
            RateLimitDecision::Denied { retry_after_ms } => assert!(retry_after_ms >= 1000),
            other => panic!("expected denial, got {other:?}"),
        }
        assert_eq!(limiter.check_at("alice", 1, 1000), RateLimitDecision::Allowed);
    }

    #[test]
    fn tracks_limits_per_key() {
        let mut limiter = RateLimitRegistry::new(1, 1);
        assert_eq!(limiter.check_at("alice", 1, 0), RateLimitDecision::Allowed);
        assert_eq!(limiter.check_at("bob", 1, 0), RateLimitDecision::Allowed);
    }
}
