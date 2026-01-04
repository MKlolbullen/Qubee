use anyhow::{Context, Result};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use blake3::Hasher;

use crate::identity::identity_key::{IdentityId, IdentityKey, HybridSignature};
use crate::groups::group_crypto::{GroupCrypto, GroupKey};
use crate::groups::group_permissions::{GroupPermissions, Permission, Role};
use crate::groups::group_events::{GroupEvent, GroupEventType, GroupEventLog};
use crate::storage::secure_keystore::{SecureKeystore, KeyType, KeyMetadata, KeyUsage};
use std::collections::HashMap as StdHashMap;
use bincode;
use hex;

/// Comprehensive group management system
pub struct GroupManager {
    groups: HashMap<GroupId, Group>,
    member_groups: HashMap<IdentityId, HashSet<GroupId>>,
    group_crypto: GroupCrypto,
    keystore: SecureKeystore,
}

/// Group information and configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub name: String,
    pub description: String,
    pub group_type: GroupType,
    pub members: HashMap<IdentityId, GroupMember>,
    pub permissions: GroupPermissions,
    pub settings: GroupSettings,
    pub metadata: GroupMetadata,
    pub created_at: u64,
    pub last_updated: u64,
    pub version: u64,
}

/// Unique identifier for a group
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId([u8; 32]);

/// Types of groups
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupType {
    /// Private group with invitation only
    Private,
    /// Public group that can be discovered
    Public,
    /// Broadcast channel (one-to-many)
    Broadcast,
    /// Announcement channel (admin-only posting)
    Announcement,
    /// Temporary group with expiration
    Temporary { expires_at: u64 },
}

/// Group member information
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub identity_id: IdentityId,
    pub identity_key: IdentityKey,
    pub display_name: String,
    pub role: Role,
    pub joined_at: u64,
    pub last_seen: u64,
    pub invited_by: Option<IdentityId>,
    pub member_status: MemberStatus,
    pub custom_permissions: Option<HashSet<Permission>>,
}

/// Member status in the group
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemberStatus {
    /// Active member
    Active,
    /// Invited but not yet joined
    Invited,
    /// Temporarily muted
    Muted { until: Option<u64> },
    /// Banned from the group
    Banned { reason: String, until: Option<u64> },
    /// Left the group voluntarily
    Left,
    /// Removed by admin
    Removed { reason: String },
}

/// Group settings and configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupSettings {
    pub max_members: Option<usize>,
    pub message_history_retention: Option<u64>, // seconds
    pub allow_member_invites: bool,
    pub require_admin_approval: bool,
    pub disappearing_messages: Option<u64>, // seconds
    pub read_receipts_enabled: bool,
    pub typing_indicators_enabled: bool,
    pub file_sharing_enabled: bool,
    pub voice_calls_enabled: bool,
    pub video_calls_enabled: bool,
    pub screen_sharing_enabled: bool,
}

/// Group metadata
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupMetadata {
    pub avatar_hash: Option<String>,
    pub tags: Vec<String>,
    pub category: Option<String>,
    pub external_links: Vec<String>,
    pub custom_fields: HashMap<String, String>,
}

/// Group invitation
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupInvitation {
    pub group_id: GroupId,
    pub group_name: String,
    pub inviter_id: IdentityId,
    pub inviter_name: String,
    pub invitation_code: String,
    pub expires_at: Option<u64>,
    pub max_uses: Option<u32>,
    pub current_uses: u32,
    pub created_at: u64,
}

/// Group join request
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupJoinRequest {
    pub group_id: GroupId,
    pub requester_id: IdentityId,
    pub requester_key: IdentityKey,
    pub message: String,
    pub created_at: u64,
}

impl GroupManager {
    /// Create a new group manager
    pub fn new(keystore: SecureKeystore) -> Result<Self> {
        let group_crypto = GroupCrypto::new()?;
        
        Ok(GroupManager {
            groups: HashMap::new(),
            member_groups: HashMap::new(),
            group_crypto,
            keystore,
        })
    }
    
    /// Create a new group
    pub fn create_group(
        &mut self,
        creator_id: IdentityId,
        creator_key: IdentityKey,
        name: String,
        description: String,
        group_type: GroupType,
        settings: GroupSettings,
    ) -> Result<GroupId> {
        let group_id = self.generate_group_id(&name, &creator_id)?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        // Create creator as admin member
        let creator_member = GroupMember {
            identity_id: creator_id,
            identity_key: creator_key,
            display_name: "Creator".to_string(), // Should be provided
            role: Role::Owner,
            joined_at: current_time,
            last_seen: current_time,
            invited_by: None,
            member_status: MemberStatus::Active,
            custom_permissions: None,
        };
        
        let mut members = HashMap::new();
        members.insert(creator_id, creator_member);
        
        let group = Group {
            id: group_id,
            name,
            description,
            group_type,
            members,
            permissions: GroupPermissions::default(),
            settings,
            metadata: GroupMetadata::default(),
            created_at: current_time,
            last_updated: current_time,
            version: 1,
        };
        
        // Generate group key
        self.group_crypto.create_group_key(group_id)?;
        
        // Store group
        self.groups.insert(group_id, group);
        self.member_groups
            .entry(creator_id)
            .or_insert_with(HashSet::new)
            .insert(group_id);
        
        // Log group creation event
        self.log_group_event(
            group_id,
            creator_id,
            GroupEventType::GroupCreated,
            format!("Group '{}' created", self.groups[&group_id].name),
        )?;
        
        // Store in keystore
        self.store_group_securely(&group_id)?;
        
        Ok(group_id)
    }
    
    /// Add a member to a group
    pub fn add_member(
        &mut self,
        group_id: GroupId,
        admin_id: IdentityId,
        new_member_id: IdentityId,
        new_member_key: IdentityKey,
        display_name: String,
        role: Role,
    ) -> Result<()> {
        // Check if admin has permission to add members
        self.check_permission(group_id, admin_id, Permission::AddMembers)?;
        
        let group = self.groups.get_mut(&group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found"))?;
        
        // Check if member already exists
        if group.members.contains_key(&new_member_id) {
            return Err(anyhow::anyhow!("Member already in group"));
        }
        
        // Check member limit
        if let Some(max_members) = group.settings.max_members {
            if group.members.len() >= max_members {
                return Err(anyhow::anyhow!("Group member limit reached"));
            }
        }
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let new_member = GroupMember {
            identity_id: new_member_id,
            identity_key: new_member_key,
            display_name,
            role,
            joined_at: current_time,
            last_seen: current_time,
            invited_by: Some(admin_id),
            member_status: MemberStatus::Active,
            custom_permissions: None,
        };
        
        group.members.insert(new_member_id, new_member);
        group.last_updated = current_time;
        group.version += 1;
        
        // Update member groups mapping
        self.member_groups
            .entry(new_member_id)
            .or_insert_with(HashSet::new)
            .insert(group_id);
        
        // Rotate group key for forward secrecy
        self.group_crypto.rotate_group_key(group_id)?;
        
        // Log event
        self.log_group_event(
            group_id,
            admin_id,
            GroupEventType::MemberAdded,
            format!("Member {} added to group", new_member_id),
        )?;
        
        self.store_group_securely(&group_id)?;
        
        Ok(())
    }
    
    /// Remove a member from a group
    pub fn remove_member(
        &mut self,
        group_id: GroupId,
        admin_id: IdentityId,
        member_id: IdentityId,
        reason: String,
    ) -> Result<()> {
        // Check permissions
        self.check_permission(group_id, admin_id, Permission::RemoveMembers)?;
        
        let group = self.groups.get_mut(&group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found"))?;
        
        // Cannot remove the owner
        if let Some(member) = group.members.get(&member_id) {
            if member.role == Role::Owner {
                return Err(anyhow::anyhow!("Cannot remove group owner"));
            }
        }
        
        // Update member status
        if let Some(member) = group.members.get_mut(&member_id) {
            member.member_status = MemberStatus::Removed { reason: reason.clone() };
            member.last_seen = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs();
        }
        
        // Update member groups mapping
        if let Some(member_groups) = self.member_groups.get_mut(&member_id) {
            member_groups.remove(&group_id);
        }
        
        group.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        group.version += 1;
        
        // Rotate group key for backward secrecy
        self.group_crypto.rotate_group_key(group_id)?;
        
        // Log event
        self.log_group_event(
            group_id,
            admin_id,
            GroupEventType::MemberRemoved,
            format!("Member {} removed: {}", member_id, reason),
        )?;
        
        self.store_group_securely(&group_id)?;
        
        Ok(())
    }
    
    /// Update member role
    pub fn update_member_role(
        &mut self,
        group_id: GroupId,
        admin_id: IdentityId,
        member_id: IdentityId,
        new_role: Role,
    ) -> Result<()> {
        // Check permissions
        self.check_permission(group_id, admin_id, Permission::ManageRoles)?;
        
        let group = self.groups.get_mut(&group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found"))?;
        
        // Cannot change owner role
        if let Some(member) = group.members.get(&member_id) {
            if member.role == Role::Owner {
                return Err(anyhow::anyhow!("Cannot change owner role"));
            }
        }
        
        // Update role
        if let Some(member) = group.members.get_mut(&member_id) {
            let old_role = member.role.clone();
            member.role = new_role.clone();
            
            // Log event
            self.log_group_event(
                group_id,
                admin_id,
                GroupEventType::RoleChanged,
                format!("Member {} role changed from {:?} to {:?}", member_id, old_role, new_role),
            )?;
        }
        
        group.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        group.version += 1;
        
        self.store_group_securely(&group_id)?;
        
        Ok(())
    }
    
    /// Create a group invitation
    pub fn create_invitation(
        &mut self,
        group_id: GroupId,
        admin_id: IdentityId,
        expires_at: Option<u64>,
        max_uses: Option<u32>,
    ) -> Result<GroupInvitation> {
        // Check permissions
        self.check_permission(group_id, admin_id, Permission::CreateInvites)?;
        
        let group = self.groups.get(&group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found"))?;
        
        let admin = group.members.get(&admin_id)
            .ok_or_else(|| anyhow::anyhow!("Admin not found in group"))?;
        
        let invitation_code = self.generate_invitation_code(group_id, admin_id)?;
        
        let invitation = GroupInvitation {
            group_id,
            group_name: group.name.clone(),
            inviter_id: admin_id,
            inviter_name: admin.display_name.clone(),
            invitation_code,
            expires_at,
            max_uses,
            current_uses: 0,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs(),
        };
        
        // Store invitation
        let invitation_key = format!("invitation_{}", invitation.invitation_code);
        let serialized = bincode::serialize(&invitation)?;
        self.keystore.store_key(&invitation_key, &serialized)?;
        
        // Log event
        self.log_group_event(
            group_id,
            admin_id,
            GroupEventType::InvitationCreated,
            format!("Invitation created with code {}", invitation.invitation_code),
        )?;
        
        Ok(invitation)
    }
    
    /// Join a group using an invitation
    pub fn join_group_with_invitation(
        &mut self,
        invitation_code: String,
        member_id: IdentityId,
        member_key: IdentityKey,
        display_name: String,
    ) -> Result<GroupId> {
        // Retrieve invitation
        let invitation_key = format!("invitation_{}", invitation_code);
        let invitation_data = self.keystore.retrieve_key(&invitation_key)?;
        let mut invitation: GroupInvitation = bincode::deserialize(&invitation_data)?;
        
        // Check invitation validity
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        if let Some(expires_at) = invitation.expires_at {
            if current_time > expires_at {
                return Err(anyhow::anyhow!("Invitation has expired"));
            }
        }
        
        if let Some(max_uses) = invitation.max_uses {
            if invitation.current_uses >= max_uses {
                return Err(anyhow::anyhow!("Invitation has reached maximum uses"));
            }
        }
        
        // Add member to group
        self.add_member(
            invitation.group_id,
            invitation.inviter_id,
            member_id,
            member_key,
            display_name,
            Role::Member,
        )?;
        
        // Update invitation usage
        invitation.current_uses += 1;
        let serialized = bincode::serialize(&invitation)?;
        self.keystore.store_key(&invitation_key, &serialized)?;
        
        Ok(invitation.group_id)
    }
    
    /// Leave a group
    pub fn leave_group(&mut self, group_id: GroupId, member_id: IdentityId) -> Result<()> {
        let group = self.groups.get_mut(&group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found"))?;
        
        // Owner cannot leave (must transfer ownership first)
        if let Some(member) = group.members.get(&member_id) {
            if member.role == Role::Owner {
                return Err(anyhow::anyhow!("Owner cannot leave group without transferring ownership"));
            }
        }
        
        // Update member status
        if let Some(member) = group.members.get_mut(&member_id) {
            member.member_status = MemberStatus::Left;
            member.last_seen = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs();
        }
        
        // Update member groups mapping
        if let Some(member_groups) = self.member_groups.get_mut(&member_id) {
            member_groups.remove(&group_id);
        }
        
        group.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        group.version += 1;
        
        // Rotate group key
        self.group_crypto.rotate_group_key(group_id)?;
        
        // Log event
        self.log_group_event(
            group_id,
            member_id,
            GroupEventType::MemberLeft,
            format!("Member {} left the group", member_id),
        )?;
        
        self.store_group_securely(&group_id)?;
        
        Ok(())
    }
    
    /// Update group settings
    pub fn update_group_settings(
        &mut self,
        group_id: GroupId,
        admin_id: IdentityId,
        new_settings: GroupSettings,
    ) -> Result<()> {
        // Check permissions
        self.check_permission(group_id, admin_id, Permission::ManageSettings)?;
        
        let group = self.groups.get_mut(&group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found"))?;
        
        group.settings = new_settings;
        group.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        group.version += 1;
        
        // Log event
        self.log_group_event(
            group_id,
            admin_id,
            GroupEventType::SettingsChanged,
            "Group settings updated".to_string(),
        )?;
        
        self.store_group_securely(&group_id)?;
        
        Ok(())
    }
    
    /// Get a group by ID
    pub fn get_group(&self, group_id: &GroupId) -> Option<&Group> {
        self.groups.get(group_id)
    }
    
    /// Get all groups for a member
    pub fn get_member_groups(&self, member_id: &IdentityId) -> Vec<&Group> {
        if let Some(group_ids) = self.member_groups.get(member_id) {
            group_ids
                .iter()
                .filter_map(|id| self.groups.get(id))
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Get active members of a group
    pub fn get_active_members(&self, group_id: &GroupId) -> Vec<&GroupMember> {
        if let Some(group) = self.groups.get(group_id) {
            group
                .members
                .values()
                .filter(|member| member.member_status == MemberStatus::Active)
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Check if a member has a specific permission
    pub fn check_permission(
        &self,
        group_id: GroupId,
        member_id: IdentityId,
        permission: Permission,
    ) -> Result<()> {
        let group = self.groups.get(&group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found"))?;
        
        let member = group.members.get(&member_id)
            .ok_or_else(|| anyhow::anyhow!("Member not found in group"))?;
        
        if member.member_status != MemberStatus::Active {
            return Err(anyhow::anyhow!("Member is not active"));
        }
        
        // Check custom permissions first
        if let Some(custom_permissions) = &member.custom_permissions {
            if custom_permissions.contains(&permission) {
                return Ok(());
            }
        }
        
        // Check role-based permissions
        if group.permissions.role_has_permission(&member.role, &permission) {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Permission denied"))
        }
    }
    
    /// Generate a unique group ID
    fn generate_group_id(&self, name: &str, creator_id: &IdentityId) -> Result<GroupId> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let mut hasher = Hasher::new();
        hasher.update(name.as_bytes());
        hasher.update(creator_id.as_ref());
        hasher.update(&current_time.to_le_bytes());
        hasher.update(b"qubee_group_id");
        
        let hash = hasher.finalize();
        Ok(GroupId(hash.as_bytes()[..32].try_into().unwrap()))
    }
    
    /// Generate an invitation code
    fn generate_invitation_code(&self, group_id: GroupId, admin_id: IdentityId) -> Result<String> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let mut hasher = Hasher::new();
        hasher.update(group_id.as_ref());
        hasher.update(admin_id.as_ref());
        hasher.update(&current_time.to_le_bytes());
        hasher.update(b"qubee_invitation");
        
        let hash = hasher.finalize();
        Ok(hex::encode(&hash.as_bytes()[..16]))
    }
    
    /// Log a group event
    fn log_group_event(
        &self,
        group_id: GroupId,
        actor_id: IdentityId,
        event_type: GroupEventType,
        description: String,
    ) -> Result<()> {
        let event = GroupEvent {
            group_id,
            actor_id,
            event_type,
            description,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs(),
        };
        
        // Store event in keystore. We classify group events as message keys
        // since they represent logged messages rather than cryptographic
        // material. The serialized event is stored under a key name that
        // includes the group ID and timestamp. We include minimal metadata
        // describing the format and size of the stored data.  
        let event_key = format!("group_event_{}_{}", group_id, event.timestamp);
        let serialized = bincode::serialize(&event)?;
        let metadata = KeyMetadata {
            algorithm: "bincode".to_string(),
            key_size: serialized.len(),
            usage: vec![KeyUsage::Encryption],
            expiry: None,
            tags: StdHashMap::new(),
        };
        self.keystore.store_key(&event_key, &serialized, KeyType::MessageKey, metadata)?;
        
        Ok(())
    }
    
    /// Store group securely
    fn store_group_securely(&self, group_id: &GroupId) -> Result<()> {
        if let Some(group) = self.groups.get(group_id) {
            let serialized = bincode::serialize(group)?;
            let key_name = format!("group_{}", hex::encode(group_id.as_ref()));
            let metadata = KeyMetadata {
                algorithm: "bincode".to_string(),
                key_size: serialized.len(),
                usage: vec![KeyUsage::Encryption],
                expiry: None,
                tags: StdHashMap::new(),
            };
            self.keystore.store_key(&key_name, &serialized, KeyType::EncryptionKey, metadata)?;
        }
        Ok(())
    }

    /// Retrieve all events logged for the given group. Events are
    /// stored in the secure keystore with keys of the form
    /// `group_event_{group_id_hex}_{timestamp}`. This method
    /// iterates over all stored keys, deserializes the corresponding
    /// events and returns them sorted by timestamp.
    pub fn get_group_events(&mut self, group_id: &GroupId) -> Result<Vec<GroupEvent>> {
        let prefix = format!("group_event_{}", hex::encode(group_id.as_ref()));
        let key_ids = self.keystore.list_keys();
        let mut events = Vec::new();
        for key_id in key_ids {
            if key_id.starts_with(&prefix) {
                if let Some(secret_data) = self.keystore.retrieve_key(&key_id)? {
                    let data = secret_data.expose_secret();
                    if let Ok(event) = bincode::deserialize::<GroupEvent>(data) {
                        events.push(event);
                    }
                }
            }
        }
        events.sort_by_key(|e| e.timestamp);
        Ok(events)
    }

    /// Encrypt a plaintext message for delivery to the specified group.
    /// This method uses the `GroupCrypto` to derive a symmetric key
    /// associated with the group and returns the ciphertext with the
    /// nonce prepended. The caller is responsible for publishing the
    /// encrypted message via the network layer (e.g. gossipsub).
    pub fn encrypt_group_message(&self, group_id: &GroupId, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.group_crypto.encrypt_message(group_id, plaintext)
    }

    /// Decrypt an incoming group message. The provided `data` should
    /// contain the nonce prefix as produced by `encrypt_group_message`.
    /// If decryption succeeds the plaintext is returned; otherwise
    /// an error is propagated.
    pub fn decrypt_group_message(&self, group_id: &GroupId, data: &[u8]) -> Result<Vec<u8>> {
        self.group_crypto.decrypt_message(group_id, data)
    }
    
    /// Load groups from storage
    pub fn load_groups_from_storage(&mut self) -> Result<()> {
        // List all keys and filter to those representing stored group objects
        let group_keys = self
            .keystore
            .list_keys()
            .into_iter()
            .filter(|key| key.starts_with("group_"))
            .collect::<Vec<_>>();

        for key_name in group_keys {
            if let Some(secret_data) = self.keystore.retrieve_key(&key_name)? {
                let data = secret_data.expose_secret();
                if let Ok(group) = bincode::deserialize::<Group>(data) {
                    let group_id = group.id;
                    // Update member groups mapping
                    for member_id in group.members.keys() {
                        self.member_groups
                            .entry(*member_id)
                            .or_insert_with(HashSet::new)
                            .insert(group_id);
                    }
                    self.groups.insert(group_id, group);
                }
            }
        }
        Ok(())
    }
}

impl GroupId {
    /// Create a new group ID from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        GroupId(bytes)
    }
    
    /// Get the bytes of the group ID
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// Get a reference to the underlying bytes
    pub fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl std::fmt::Debug for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupId({})", hex::encode(&self.0[..8]))
    }
}

impl Default for GroupSettings {
    fn default() -> Self {
        GroupSettings {
            max_members: Some(1000),
            message_history_retention: None,
            allow_member_invites: true,
            require_admin_approval: false,
            disappearing_messages: None,
            read_receipts_enabled: true,
            typing_indicators_enabled: true,
            file_sharing_enabled: true,
            voice_calls_enabled: true,
            video_calls_enabled: true,
            screen_sharing_enabled: false,
        }
    }
}

impl Default for GroupMetadata {
    fn default() -> Self {
        GroupMetadata {
            avatar_hash: None,
            tags: Vec::new(),
            category: None,
            external_links: Vec::new(),
            custom_fields: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::identity_key::IdentityKeyPair;
    use tempfile::TempDir;
    
    #[test]
    fn test_group_creation() {
        // Create a temporary keystore for testing
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keystore_path = temp_dir.path().join("group_keystore.db");
        let keystore = SecureKeystore::new(keystore_path).expect("Should create keystore");
        let mut group_manager = GroupManager::new(keystore).expect("Should create group manager");
        
        let creator_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let creator_key = creator_keypair.public_key();
        let creator_id = creator_key.identity_id;
        
        let group_id = group_manager.create_group(
            creator_id,
            creator_key,
            "Test Group".to_string(),
            "A test group".to_string(),
            GroupType::Private,
            GroupSettings::default(),
        ).expect("Should create group");
        
        let group = group_manager.get_group(&group_id).expect("Should find group");
        assert_eq!(group.name, "Test Group");
        assert_eq!(group.members.len(), 1);
        assert!(group.members.contains_key(&creator_id));
        assert_eq!(group.members[&creator_id].role, Role::Owner);
    }
    
    #[test]
    fn test_member_management() {
        // Create a temporary keystore for testing
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keystore_path = temp_dir.path().join("group_keystore.db");
        let keystore = SecureKeystore::new(keystore_path).expect("Should create keystore");
        let mut group_manager = GroupManager::new(keystore).expect("Should create group manager");
        
        let creator_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let creator_key = creator_keypair.public_key();
        let creator_id = creator_key.identity_id;
        
        let member_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let member_key = member_keypair.public_key();
        let member_id = member_key.identity_id;
        
        let group_id = group_manager.create_group(
            creator_id,
            creator_key,
            "Test Group".to_string(),
            "A test group".to_string(),
            GroupType::Private,
            GroupSettings::default(),
        ).expect("Should create group");
        
        // Add member
        group_manager.add_member(
            group_id,
            creator_id,
            member_id,
            member_key,
            "Test Member".to_string(),
            Role::Member,
        ).expect("Should add member");
        
        let group = group_manager.get_group(&group_id).expect("Should find group");
        assert_eq!(group.members.len(), 2);
        assert!(group.members.contains_key(&member_id));
        
        // Update role
        group_manager.update_member_role(
            group_id,
            creator_id,
            member_id,
            Role::Admin,
        ).expect("Should update role");
        
        let group = group_manager.get_group(&group_id).expect("Should find group");
        assert_eq!(group.members[&member_id].role, Role::Admin);
        
        // Remove member
        group_manager.remove_member(
            group_id,
            creator_id,
            member_id,
            "Test removal".to_string(),
        ).expect("Should remove member");
        
        let group = group_manager.get_group(&group_id).expect("Should find group");
        assert_eq!(group.members[&member_id].member_status, MemberStatus::Removed { reason: "Test removal".to_string() });
    }
    
    #[test]
    fn test_group_invitations() {
        // Create a temporary keystore for testing
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keystore_path = temp_dir.path().join("group_keystore.db");
        let keystore = SecureKeystore::new(keystore_path).expect("Should create keystore");
        let mut group_manager = GroupManager::new(keystore).expect("Should create group manager");
        
        let creator_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let creator_key = creator_keypair.public_key();
        let creator_id = creator_key.identity_id;
        
        let group_id = group_manager.create_group(
            creator_id,
            creator_key,
            "Test Group".to_string(),
            "A test group".to_string(),
            GroupType::Private,
            GroupSettings::default(),
        ).expect("Should create group");
        
        // Create invitation
        let invitation = group_manager.create_invitation(
            group_id,
            creator_id,
            None,
            Some(5),
        ).expect("Should create invitation");
        
        assert_eq!(invitation.group_id, group_id);
        assert_eq!(invitation.max_uses, Some(5));
        assert_eq!(invitation.current_uses, 0);
        
        // Join with invitation
        let joiner_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let joiner_key = joiner_keypair.public_key();
        let joiner_id = joiner_key.identity_id;
        
        let joined_group_id = group_manager.join_group_with_invitation(
            invitation.invitation_code,
            joiner_id,
            joiner_key,
            "Joiner".to_string(),
        ).expect("Should join group");
        
        assert_eq!(joined_group_id, group_id);
        
        let group = group_manager.get_group(&group_id).expect("Should find group");
        assert_eq!(group.members.len(), 2);
        assert!(group.members.contains_key(&joiner_id));
    }
}

