pub mod group_manager;
pub mod group_crypto;
pub mod group_permissions;
pub mod group_events;
pub mod group_invite;
pub mod group_handshake;
pub mod group_message;
pub mod handshake_handlers;

pub use group_manager::{Group, GroupId, GroupManager, GroupMember, QUBEE_MAX_GROUP_MEMBERS};
pub use group_crypto::{GroupCrypto, GroupKey, GroupKeyRotation};
pub use group_permissions::{GroupPermissions, Permission, Role};
pub use group_events::{GroupEvent, GroupEventLog, GroupEventType};
pub use group_invite::{InvitePayload, QUBEE_INVITE_HOST, QUBEE_URI_SCHEME};
pub use group_handshake::{
    GroupHandshake, GroupMemberSummary, JoinAcceptedBody, JoinRejectedBody, KeyRotationBody,
    MemberKeyDelivery, RequestJoinBody,
};
pub use group_message::{
    decrypt_group_message, encrypt_group_message, DecryptedGroupMessage, GroupMessageBody,
    GroupMessageEnvelope, GROUP_MESSAGE_MAX_AGE_SECS, MAGIC_GROUP_MESSAGE,
};