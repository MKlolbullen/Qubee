use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

/// Group permissions system with role-based access control
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupPermissions {
    /// Default permissions for each role
    pub role_permissions: HashMap<Role, HashSet<Permission>>,
    /// Custom permission overrides
    pub custom_overrides: HashMap<String, HashSet<Permission>>,
}

/// Roles within a group
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub enum Role {
    /// Group owner with all permissions
    Owner,
    /// Administrator with most permissions
    Admin,
    /// Moderator with limited admin permissions
    Moderator,
    /// Regular member
    Member,
    /// Read-only member
    Observer,
    /// Custom role with specific permissions
    Custom(String),
}

/// Specific permissions within a group
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub enum Permission {
    // Member management
    AddMembers,
    RemoveMembers,
    BanMembers,
    UnbanMembers,
    
    // Role management
    ManageRoles,
    AssignModerator,
    AssignAdmin,
    
    // Group management
    ManageSettings,
    ChangeGroupName,
    ChangeGroupDescription,
    ChangeGroupAvatar,
    DeleteGroup,
    
    // Invitation management
    CreateInvites,
    RevokeInvites,
    ManageInviteSettings,
    
    // Message management
    SendMessages,
    DeleteOwnMessages,
    DeleteAnyMessage,
    EditOwnMessages,
    EditAnyMessage,
    PinMessages,
    UnpinMessages,
    
    // Media and file sharing
    SendFiles,
    SendImages,
    SendVideos,
    SendAudio,
    SendDocuments,
    
    // Communication features
    StartVoiceCall,
    StartVideoCall,
    StartScreenShare,
    ManageCallSettings,
    
    // Moderation
    MuteMembers,
    UnmuteMembers,
    SetSlowMode,
    ManageAutoModeration,
    
    // Advanced features
    CreatePolls,
    ManagePolls,
    CreateEvents,
    ManageEvents,
    AccessAuditLog,
    ManageIntegrations,
    
    // Read permissions
    ReadMessages,
    ReadMemberList,
    ReadGroupInfo,
    
    // Custom permissions
    Custom(String),
}

/// Permission level for fine-grained control
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum PermissionLevel {
    /// No access
    None,
    /// Read-only access
    Read,
    /// Read and write access
    Write,
    /// Full administrative access
    Admin,
}

/// Permission context for conditional permissions
#[derive(Clone, Serialize, Deserialize)]
pub struct PermissionContext {
    /// Time-based restrictions
    pub time_restrictions: Option<TimeRestriction>,
    /// Member count restrictions
    pub member_count_restrictions: Option<MemberCountRestriction>,
    /// Content type restrictions
    pub content_restrictions: Option<ContentRestriction>,
}

/// Time-based permission restrictions
#[derive(Clone, Serialize, Deserialize)]
pub struct TimeRestriction {
    /// Allowed hours (0-23)
    pub allowed_hours: Option<Vec<u8>>,
    /// Allowed days of week (0-6, 0=Sunday)
    pub allowed_days: Option<Vec<u8>>,
    /// Cooldown period between actions (seconds)
    pub cooldown_period: Option<u64>,
}

/// Member count-based restrictions
#[derive(Clone, Serialize, Deserialize)]
pub struct MemberCountRestriction {
    /// Minimum members required for action
    pub min_members: Option<usize>,
    /// Maximum members allowed for action
    pub max_members: Option<usize>,
}

/// Content-based restrictions
#[derive(Clone, Serialize, Deserialize)]
pub struct ContentRestriction {
    /// Maximum file size (bytes)
    pub max_file_size: Option<u64>,
    /// Allowed file types
    pub allowed_file_types: Option<Vec<String>>,
    /// Maximum message length
    pub max_message_length: Option<usize>,
}

impl GroupPermissions {
    /// Create default permissions for a standard group
    pub fn default() -> Self {
        let mut role_permissions = HashMap::new();
        
        // Owner permissions (all permissions)
        let owner_permissions = Self::all_permissions();
        role_permissions.insert(Role::Owner, owner_permissions);
        
        // Admin permissions (most permissions except ownership transfer)
        let mut admin_permissions = Self::all_permissions();
        admin_permissions.remove(&Permission::DeleteGroup);
        admin_permissions.remove(&Permission::AssignAdmin);
        role_permissions.insert(Role::Admin, admin_permissions);
        
        // Moderator permissions (moderation and basic management)
        let moderator_permissions = hashset![
            Permission::AddMembers,
            Permission::RemoveMembers,
            Permission::BanMembers,
            Permission::UnbanMembers,
            Permission::MuteMembers,
            Permission::UnmuteMembers,
            Permission::DeleteAnyMessage,
            Permission::PinMessages,
            Permission::UnpinMessages,
            Permission::SetSlowMode,
            Permission::ManageAutoModeration,
            Permission::SendMessages,
            Permission::DeleteOwnMessages,
            Permission::EditOwnMessages,
            Permission::SendFiles,
            Permission::SendImages,
            Permission::SendVideos,
            Permission::SendAudio,
            Permission::SendDocuments,
            Permission::StartVoiceCall,
            Permission::StartVideoCall,
            Permission::ReadMessages,
            Permission::ReadMemberList,
            Permission::ReadGroupInfo,
        ];
        role_permissions.insert(Role::Moderator, moderator_permissions);
        
        // Member permissions (basic communication)
        let member_permissions = hashset![
            Permission::SendMessages,
            Permission::DeleteOwnMessages,
            Permission::EditOwnMessages,
            Permission::SendFiles,
            Permission::SendImages,
            Permission::SendVideos,
            Permission::SendAudio,
            Permission::SendDocuments,
            Permission::StartVoiceCall,
            Permission::StartVideoCall,
            Permission::CreatePolls,
            Permission::ReadMessages,
            Permission::ReadMemberList,
            Permission::ReadGroupInfo,
        ];
        role_permissions.insert(Role::Member, member_permissions);
        
        // Observer permissions (read-only)
        let observer_permissions = hashset![
            Permission::ReadMessages,
            Permission::ReadMemberList,
            Permission::ReadGroupInfo,
        ];
        role_permissions.insert(Role::Observer, observer_permissions);
        
        GroupPermissions {
            role_permissions,
            custom_overrides: HashMap::new(),
        }
    }
    
    /// Create permissions for a broadcast channel
    pub fn broadcast_channel() -> Self {
        let mut permissions = Self::default();
        
        // Only admins can send messages in broadcast channels
        let member_permissions = hashset![
            Permission::ReadMessages,
            Permission::ReadMemberList,
            Permission::ReadGroupInfo,
        ];
        permissions.role_permissions.insert(Role::Member, member_permissions);
        
        permissions
    }
    
    /// Create permissions for an announcement channel
    pub fn announcement_channel() -> Self {
        let mut permissions = Self::broadcast_channel();
        
        // Even more restrictive - only owners can send messages
        let admin_permissions = hashset![
            Permission::AddMembers,
            Permission::RemoveMembers,
            Permission::BanMembers,
            Permission::UnbanMembers,
            Permission::MuteMembers,
            Permission::UnmuteMembers,
            Permission::ManageRoles,
            Permission::ManageSettings,
            Permission::CreateInvites,
            Permission::RevokeInvites,
            Permission::ReadMessages,
            Permission::ReadMemberList,
            Permission::ReadGroupInfo,
            Permission::AccessAuditLog,
        ];
        permissions.role_permissions.insert(Role::Admin, admin_permissions);
        
        permissions
    }
    
    /// Check if a role has a specific permission
    pub fn role_has_permission(&self, role: &Role, permission: &Permission) -> bool {
        if let Some(permissions) = self.role_permissions.get(role) {
            permissions.contains(permission)
        } else {
            false
        }
    }
    
    /// Add a permission to a role
    pub fn add_permission_to_role(&mut self, role: Role, permission: Permission) {
        self.role_permissions
            .entry(role)
            .or_insert_with(HashSet::new)
            .insert(permission);
    }
    
    /// Remove a permission from a role
    pub fn remove_permission_from_role(&mut self, role: &Role, permission: &Permission) {
        if let Some(permissions) = self.role_permissions.get_mut(role) {
            permissions.remove(permission);
        }
    }
    
    /// Create a custom role with specific permissions
    pub fn create_custom_role(&mut self, role_name: String, permissions: HashSet<Permission>) {
        let custom_role = Role::Custom(role_name);
        self.role_permissions.insert(custom_role, permissions);
    }
    
    /// Get all permissions for a role
    pub fn get_role_permissions(&self, role: &Role) -> HashSet<Permission> {
        self.role_permissions
            .get(role)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Check if a permission is valid for the group type
    pub fn is_permission_valid(&self, permission: &Permission) -> bool {
        match permission {
            Permission::Custom(_) => true, // Custom permissions are always valid
            _ => true, // All standard permissions are valid by default
        }
    }
    
    /// Get all available permissions
    fn all_permissions() -> HashSet<Permission> {
        hashset![
            // Member management
            Permission::AddMembers,
            Permission::RemoveMembers,
            Permission::BanMembers,
            Permission::UnbanMembers,
            
            // Role management
            Permission::ManageRoles,
            Permission::AssignModerator,
            Permission::AssignAdmin,
            
            // Group management
            Permission::ManageSettings,
            Permission::ChangeGroupName,
            Permission::ChangeGroupDescription,
            Permission::ChangeGroupAvatar,
            Permission::DeleteGroup,
            
            // Invitation management
            Permission::CreateInvites,
            Permission::RevokeInvites,
            Permission::ManageInviteSettings,
            
            // Message management
            Permission::SendMessages,
            Permission::DeleteOwnMessages,
            Permission::DeleteAnyMessage,
            Permission::EditOwnMessages,
            Permission::EditAnyMessage,
            Permission::PinMessages,
            Permission::UnpinMessages,
            
            // Media and file sharing
            Permission::SendFiles,
            Permission::SendImages,
            Permission::SendVideos,
            Permission::SendAudio,
            Permission::SendDocuments,
            
            // Communication features
            Permission::StartVoiceCall,
            Permission::StartVideoCall,
            Permission::StartScreenShare,
            Permission::ManageCallSettings,
            
            // Moderation
            Permission::MuteMembers,
            Permission::UnmuteMembers,
            Permission::SetSlowMode,
            Permission::ManageAutoModeration,
            
            // Advanced features
            Permission::CreatePolls,
            Permission::ManagePolls,
            Permission::CreateEvents,
            Permission::ManageEvents,
            Permission::AccessAuditLog,
            Permission::ManageIntegrations,
            
            // Read permissions
            Permission::ReadMessages,
            Permission::ReadMemberList,
            Permission::ReadGroupInfo,
        ]
    }
    
    /// Check if one role is higher than another
    pub fn is_role_higher(&self, role1: &Role, role2: &Role) -> bool {
        let hierarchy = self.get_role_hierarchy();
        let level1 = hierarchy.get(role1).unwrap_or(&0);
        let level2 = hierarchy.get(role2).unwrap_or(&0);
        level1 > level2
    }
    
    /// Get role hierarchy levels
    fn get_role_hierarchy(&self) -> HashMap<Role, u8> {
        let mut hierarchy = HashMap::new();
        hierarchy.insert(Role::Owner, 100);
        hierarchy.insert(Role::Admin, 80);
        hierarchy.insert(Role::Moderator, 60);
        hierarchy.insert(Role::Member, 40);
        hierarchy.insert(Role::Observer, 20);
        hierarchy
    }
    
    /// Validate permission change
    pub fn can_modify_role(&self, modifier_role: &Role, target_role: &Role) -> bool {
        // Owners can modify any role
        if *modifier_role == Role::Owner {
            return true;
        }
        
        // Admins can modify roles below them
        if *modifier_role == Role::Admin {
            return !matches!(target_role, Role::Owner | Role::Admin);
        }
        
        // Moderators can only modify members and observers
        if *modifier_role == Role::Moderator {
            return matches!(target_role, Role::Member | Role::Observer);
        }
        
        false
    }
}

impl Default for PermissionContext {
    fn default() -> Self {
        PermissionContext {
            time_restrictions: None,
            member_count_restrictions: None,
            content_restrictions: None,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Owner => write!(f, "Owner"),
            Role::Admin => write!(f, "Admin"),
            Role::Moderator => write!(f, "Moderator"),
            Role::Member => write!(f, "Member"),
            Role::Observer => write!(f, "Observer"),
            Role::Custom(name) => write!(f, "Custom({})", name),
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::AddMembers => write!(f, "Add Members"),
            Permission::RemoveMembers => write!(f, "Remove Members"),
            Permission::BanMembers => write!(f, "Ban Members"),
            Permission::UnbanMembers => write!(f, "Unban Members"),
            Permission::ManageRoles => write!(f, "Manage Roles"),
            Permission::AssignModerator => write!(f, "Assign Moderator"),
            Permission::AssignAdmin => write!(f, "Assign Admin"),
            Permission::ManageSettings => write!(f, "Manage Settings"),
            Permission::ChangeGroupName => write!(f, "Change Group Name"),
            Permission::ChangeGroupDescription => write!(f, "Change Group Description"),
            Permission::ChangeGroupAvatar => write!(f, "Change Group Avatar"),
            Permission::DeleteGroup => write!(f, "Delete Group"),
            Permission::CreateInvites => write!(f, "Create Invites"),
            Permission::RevokeInvites => write!(f, "Revoke Invites"),
            Permission::ManageInviteSettings => write!(f, "Manage Invite Settings"),
            Permission::SendMessages => write!(f, "Send Messages"),
            Permission::DeleteOwnMessages => write!(f, "Delete Own Messages"),
            Permission::DeleteAnyMessage => write!(f, "Delete Any Message"),
            Permission::EditOwnMessages => write!(f, "Edit Own Messages"),
            Permission::EditAnyMessage => write!(f, "Edit Any Message"),
            Permission::PinMessages => write!(f, "Pin Messages"),
            Permission::UnpinMessages => write!(f, "Unpin Messages"),
            Permission::SendFiles => write!(f, "Send Files"),
            Permission::SendImages => write!(f, "Send Images"),
            Permission::SendVideos => write!(f, "Send Videos"),
            Permission::SendAudio => write!(f, "Send Audio"),
            Permission::SendDocuments => write!(f, "Send Documents"),
            Permission::StartVoiceCall => write!(f, "Start Voice Call"),
            Permission::StartVideoCall => write!(f, "Start Video Call"),
            Permission::StartScreenShare => write!(f, "Start Screen Share"),
            Permission::ManageCallSettings => write!(f, "Manage Call Settings"),
            Permission::MuteMembers => write!(f, "Mute Members"),
            Permission::UnmuteMembers => write!(f, "Unmute Members"),
            Permission::SetSlowMode => write!(f, "Set Slow Mode"),
            Permission::ManageAutoModeration => write!(f, "Manage Auto Moderation"),
            Permission::CreatePolls => write!(f, "Create Polls"),
            Permission::ManagePolls => write!(f, "Manage Polls"),
            Permission::CreateEvents => write!(f, "Create Events"),
            Permission::ManageEvents => write!(f, "Manage Events"),
            Permission::AccessAuditLog => write!(f, "Access Audit Log"),
            Permission::ManageIntegrations => write!(f, "Manage Integrations"),
            Permission::ReadMessages => write!(f, "Read Messages"),
            Permission::ReadMemberList => write!(f, "Read Member List"),
            Permission::ReadGroupInfo => write!(f, "Read Group Info"),
            Permission::Custom(name) => write!(f, "Custom({})", name),
        }
    }
}

// Macro to create HashSet more easily
macro_rules! hashset {
    ($($item:expr),* $(,)?) => {{
        let mut set = HashSet::new();
        $(set.insert($item);)*
        set
    }};
}

// Make the macro available for use
pub(crate) use hashset;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_permissions() {
        let permissions = GroupPermissions::default();
        
        // Owner should have all permissions
        assert!(permissions.role_has_permission(&Role::Owner, &Permission::DeleteGroup));
        assert!(permissions.role_has_permission(&Role::Owner, &Permission::SendMessages));
        
        // Member should have basic permissions
        assert!(permissions.role_has_permission(&Role::Member, &Permission::SendMessages));
        assert!(!permissions.role_has_permission(&Role::Member, &Permission::DeleteGroup));
        
        // Observer should only have read permissions
        assert!(permissions.role_has_permission(&Role::Observer, &Permission::ReadMessages));
        assert!(!permissions.role_has_permission(&Role::Observer, &Permission::SendMessages));
    }
    
    #[test]
    fn test_broadcast_channel_permissions() {
        let permissions = GroupPermissions::broadcast_channel();
        
        // Members should not be able to send messages in broadcast channels
        assert!(!permissions.role_has_permission(&Role::Member, &Permission::SendMessages));
        assert!(permissions.role_has_permission(&Role::Member, &Permission::ReadMessages));
        
        // Admins should still be able to send messages
        assert!(permissions.role_has_permission(&Role::Admin, &Permission::SendMessages));
    }
    
    #[test]
    fn test_role_hierarchy() {
        let permissions = GroupPermissions::default();
        
        assert!(permissions.is_role_higher(&Role::Owner, &Role::Admin));
        assert!(permissions.is_role_higher(&Role::Admin, &Role::Moderator));
        assert!(permissions.is_role_higher(&Role::Moderator, &Role::Member));
        assert!(permissions.is_role_higher(&Role::Member, &Role::Observer));
        
        assert!(!permissions.is_role_higher(&Role::Member, &Role::Admin));
    }
    
    #[test]
    fn test_role_modification_permissions() {
        let permissions = GroupPermissions::default();
        
        // Owner can modify any role
        assert!(permissions.can_modify_role(&Role::Owner, &Role::Admin));
        assert!(permissions.can_modify_role(&Role::Owner, &Role::Member));
        
        // Admin can modify lower roles but not owner or other admins
        assert!(!permissions.can_modify_role(&Role::Admin, &Role::Owner));
        assert!(!permissions.can_modify_role(&Role::Admin, &Role::Admin));
        assert!(permissions.can_modify_role(&Role::Admin, &Role::Member));
        
        // Moderator can only modify members and observers
        assert!(!permissions.can_modify_role(&Role::Moderator, &Role::Admin));
        assert!(permissions.can_modify_role(&Role::Moderator, &Role::Member));
        assert!(permissions.can_modify_role(&Role::Moderator, &Role::Observer));
        
        // Members cannot modify roles
        assert!(!permissions.can_modify_role(&Role::Member, &Role::Observer));
    }
    
    #[test]
    fn test_custom_role_creation() {
        let mut permissions = GroupPermissions::default();
        
        let custom_permissions = hashset![
            Permission::SendMessages,
            Permission::SendImages,
            Permission::ReadMessages,
        ];
        
        permissions.create_custom_role("ImagePoster".to_string(), custom_permissions.clone());
        
        let custom_role = Role::Custom("ImagePoster".to_string());
        assert_eq!(permissions.get_role_permissions(&custom_role), custom_permissions);
        
        assert!(permissions.role_has_permission(&custom_role, &Permission::SendImages));
        assert!(!permissions.role_has_permission(&custom_role, &Permission::DeleteAnyMessage));
    }
    
    #[test]
    fn test_permission_modification() {
        let mut permissions = GroupPermissions::default();
        
        // Remove a permission from members
        permissions.remove_permission_from_role(&Role::Member, &Permission::SendFiles);
        assert!(!permissions.role_has_permission(&Role::Member, &Permission::SendFiles));
        
        // Add a permission to observers
        permissions.add_permission_to_role(Role::Observer, Permission::SendMessages);
        assert!(permissions.role_has_permission(&Role::Observer, &Permission::SendMessages));
    }
}
