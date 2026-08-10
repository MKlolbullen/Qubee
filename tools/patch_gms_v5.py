from pathlib import Path
import re


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one anchor, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))


def replace_between(path: str, start: str, end: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    i = text.find(start)
    if i < 0:
        raise SystemExit(f"{path}: start marker missing: {start[:100]!r}")
    j = text.find(end, i)
    if j < 0:
        raise SystemExit(f"{path}: end marker missing: {end[:100]!r}")
    p.write_text(text[:i] + new + text[j:])


# ---------------------------------------------------------------------------
# Rust sender-key wire: x05 hides group id, x03 remains receive-only.
# ---------------------------------------------------------------------------
replace_once(
    "src/ratchet/sender_keys.rs",
    '''/// Magic prefix for a v3 (sender-keys) group message frame. Coexists\n/// with the v2 `\\x02` symmetric format during the migration window.\npub const MAGIC_GROUP_MESSAGE_V3: &[u8] = b"QUBEE_GMS\\x03";\n\nconst OUTER_V3_KDF_CONTEXT: &str = "qubee outer envelope v3";\n''',
    '''/// Legacy sender-key group frame. `\\x03` exposed the raw 32-byte\n/// GroupId in its outer header. It remains receive-only for an upgrade\n/// window so queued frames from older builds are not lost.\npub const MAGIC_GROUP_MESSAGE_V3: &[u8] = b"QUBEE_GMS\\x03";\n\n/// Current sender-key group frame. `\\x05` removes the last plaintext\n/// group identifier: `MAGIC || nonce(12) || selector(16) || ciphertext`.\n/// The sender identity already lives inside the sealed inner message.\npub const MAGIC_GROUP_MESSAGE_V5: &[u8] = b"QUBEE_GMS\\x05";\n\npub const GROUP_SELECTOR_V5_LEN: usize = 16;\nconst OUTER_V3_KDF_CONTEXT: &str = "qubee outer envelope v3";\nconst OUTER_V5_KDF_CONTEXT: &str = "qubee outer envelope v5";\nconst GROUP_SELECTOR_V5_KDF_CONTEXT: &str = "qubee sender-key group selector v1";\n''',
)

replace_once(
    "src/ratchet/sender_keys.rs",
    '    seal_outer_v3(group, group_key, &inner)\n',
    '    seal_outer_v5(group, group_key, &inner)\n',
)

# Replace decryption with a shared authenticated-inner step plus a universal
# migration dispatcher. The legacy direct-key function is retained for tests /
# callers explicitly decoding x03.
replace_between(
    "src/ratchet/sender_keys.rs",
    '''/// Decrypt a v3 frame. Returns `(group_id, sender_id, plaintext)`.\n''',
    '''/// Advance (or reach back into the skipped store of) a receive chain to\n''',
    '''/// Validate/decrypt the already-opened sender-key inner message. The group\n/// id comes from authenticated outer routing (x05 candidate-AAD binding) or\n/// from the legacy x03 header after its outer AEAD succeeds.\nfn decrypt_sender_key_inner(\n    ks: &mut SecureKeyStore,\n    group: GroupId,\n    inner: &[u8],\n) -> Result<(GroupId, IdentityId, Vec<u8>)> {\n    let msg: SenderKeyMessage = bounded_bincode_deserialize(inner)?;\n\n    let mut state = load_recv_state(ks, &group, &msg.sender_id)?\n        .ok_or_else(|| anyhow!("no sender key installed for this group member"))?;\n\n    let verifying = VerifyingKey::from_bytes(&state.signing_pub)\n        .map_err(|e| anyhow!("stored signing key invalid: {e}"))?;\n    let sig_bytes: [u8; 64] = msg\n        .signature\n        .as_slice()\n        .try_into()\n        .map_err(|_| anyhow!("malformed signature length"))?;\n    verifying\n        .verify(\n            &signature_digest(&group, &msg.sender_id, msg.iteration, &msg.payload),\n            &Signature::from_bytes(&sig_bytes),\n        )\n        .map_err(|_| anyhow!("sender key signature verification failed"))?;\n\n    let mut mk = take_message_key(&mut state, msg.iteration)?;\n    let (key, nonce) = derive_msg_aead(&mk)?;\n    mk.zeroize();\n    let cipher = ChaCha20Poly1305::new(&key.into());\n    let padded = cipher\n        .decrypt(\n            Nonce::from_slice(&nonce),\n            Payload {\n                msg: &msg.payload,\n                aad: &inner_aad(&group, &msg.sender_id, msg.iteration),\n            },\n        )\n        .map_err(|_| anyhow!("sender message decrypt failed (tamper)"))?;\n    let plaintext = crate::security::padding::unpad(&padded)?;\n\n    // Receive state persists only after every authentication/decrypt step passes.\n    store_recv_state(ks, &group, &msg.sender_id, &state)?;\n    Ok((group, msg.sender_id, plaintext))\n}\n\n/// Legacy x03 decoder for callers that already know the group key. New code\n/// should use [`decrypt_sender_key_message_candidates`] so x05 can resolve its\n/// anonymous outer route without exposing GroupId on the wire.\npub fn decrypt_sender_key_message(\n    ks: &mut SecureKeyStore,\n    group_key: &[u8; 32],\n    wire: &[u8],\n) -> Result<(GroupId, IdentityId, Vec<u8>)> {\n    let (group, inner) = open_outer_v3(group_key, wire)?;\n    decrypt_sender_key_inner(ks, group, &inner)\n}\n\n/// Decode either the current anonymous x05 sender-key frame or a legacy x03\n/// frame. Candidate keys come from `GroupManager::group_key_candidates()`.\n/// x05 selection is a cheap keyed-BLAKE3 scan; only matching selectors pay\n/// for AEAD, and a matching-selector AEAD failure continues to later candidates.\npub fn decrypt_sender_key_message_candidates(\n    ks: &mut SecureKeyStore,\n    candidates: impl IntoIterator<Item = (GroupId, [u8; 32])>,\n    wire: &[u8],\n) -> Result<(GroupId, IdentityId, Vec<u8>)> {\n    let (group, inner) = if is_group_message_v5_frame(wire) {\n        open_outer_v5(wire, candidates)?\n    } else if is_group_message_v3_frame(wire) {\n        let group = peek_v3_group_id(wire).ok_or_else(|| anyhow!("truncated legacy x03 frame"))?;\n        let group_key = candidates\n            .into_iter()\n            .find_map(|(gid, key)| (gid == group).then_some(key))\n            .ok_or_else(|| anyhow!("legacy x03 frame names an unknown group"))?;\n        let (opened_group, inner) = open_outer_v3(&group_key, wire)?;\n        if opened_group != group {\n            bail!("legacy x03 group mismatch after outer decrypt");\n        }\n        (group, inner)\n    } else {\n        bail!("not a sender-key group frame");\n    };\n    decrypt_sender_key_inner(ks, group, &inner)\n}\n\n''',
)

replace_once(
    "src/ratchet/sender_keys.rs",
    '''/// Cheap dispatcher probe for the v3 magic.\npub fn is_group_message_v3_frame(wire: &[u8]) -> bool {\n    wire.len() >= MAGIC_GROUP_MESSAGE_V3.len()\n        && &wire[..MAGIC_GROUP_MESSAGE_V3.len()] == MAGIC_GROUP_MESSAGE_V3\n}\n''',
    '''/// Cheap dispatcher probe for the receive-only legacy x03 magic.\npub fn is_group_message_v3_frame(wire: &[u8]) -> bool {\n    wire.len() >= MAGIC_GROUP_MESSAGE_V3.len()\n        && &wire[..MAGIC_GROUP_MESSAGE_V3.len()] == MAGIC_GROUP_MESSAGE_V3\n}\n\n/// Cheap dispatcher probe for the current anonymous x05 magic.\npub fn is_group_message_v5_frame(wire: &[u8]) -> bool {\n    wire.len() >= MAGIC_GROUP_MESSAGE_V5.len()\n        && &wire[..MAGIC_GROUP_MESSAGE_V5.len()] == MAGIC_GROUP_MESSAGE_V5\n}\n\n/// True for either sender-key wire generation accepted during migration.\npub fn is_sender_key_group_frame(wire: &[u8]) -> bool {\n    is_group_message_v5_frame(wire) || is_group_message_v3_frame(wire)\n}\n''',
)

# Universal ID extraction while keeping the old x03 helper for compatibility.
replace_once(
    "src/ratchet/sender_keys.rs",
    '''/// Open a sealed v3 frame with `group_key` and compute its\n/// [`v3_message_id`]. `None` if the bytes aren't a valid v3 envelope\n/// under this key.\npub fn extract_v3_message_id(group_key: &[u8; 32], wire: &[u8]) -> Option<[u8; 16]> {\n    let (group, inner) = open_outer_v3(group_key, wire).ok()?;\n    let msg: SenderKeyMessage = bounded_bincode_deserialize(&inner).ok()?;\n    Some(v3_message_id(\n        &group,\n        &msg.sender_id,\n        msg.iteration,\n        &msg.payload,\n    ))\n}\n''',
    '''/// Resolve either x05 or receive-only x03 and compute its stable logical\n/// message id. This is the JNI-facing extractor used by both sender and receiver.\npub fn extract_sender_key_message_id(\n    candidates: impl IntoIterator<Item = (GroupId, [u8; 32])>,\n    wire: &[u8],\n) -> Option<[u8; 16]> {\n    let (group, inner) = if is_group_message_v5_frame(wire) {\n        open_outer_v5(wire, candidates).ok()?\n    } else if is_group_message_v3_frame(wire) {\n        let group = peek_v3_group_id(wire)?;\n        let key = candidates\n            .into_iter()\n            .find_map(|(gid, key)| (gid == group).then_some(key))?;\n        let (opened, inner) = open_outer_v3(&key, wire).ok()?;\n        if opened != group {\n            return None;\n        }\n        (group, inner)\n    } else {\n        return None;\n    };\n    let msg: SenderKeyMessage = bounded_bincode_deserialize(&inner).ok()?;\n    Some(v3_message_id(\n        &group,\n        &msg.sender_id,\n        msg.iteration,\n        &msg.payload,\n    ))\n}\n\n/// Legacy x03-only extractor retained for the migration parser/fuzz surface.\npub fn extract_v3_message_id(group_key: &[u8; 32], wire: &[u8]) -> Option<[u8; 16]> {\n    let (group, inner) = open_outer_v3(group_key, wire).ok()?;\n    let msg: SenderKeyMessage = bounded_bincode_deserialize(&inner).ok()?;\n    Some(v3_message_id(\n        &group,\n        &msg.sender_id,\n        msg.iteration,\n        &msg.payload,\n    ))\n}\n''',
)

# Insert x05 anonymous outer envelope immediately before the legacy v3 key KDF.
replace_once(
    "src/ratchet/sender_keys.rs",
    '''fn derive_outer_v3_key(group_key: &[u8; 32]) -> [u8; 32] {\n''',
    '''fn derive_outer_v5_key(group_key: &[u8; 32]) -> [u8; 32] {\n    blake3::derive_key(OUTER_V5_KDF_CONTEXT, group_key)\n}\n\n/// Per-message anonymous group routing selector. 128 bits makes accidental\n/// collisions negligible even across many groups, while nonce salting prevents\n/// an observer from linking two frames from the same group.\npub fn group_selector_v5(\n    group_key: &[u8; 32],\n    nonce: &[u8; 12],\n) -> [u8; GROUP_SELECTOR_V5_LEN] {\n    let selector_key = blake3::derive_key(GROUP_SELECTOR_V5_KDF_CONTEXT, group_key);\n    let full = blake3::keyed_hash(&selector_key, nonce);\n    let mut out = [0u8; GROUP_SELECTOR_V5_LEN];\n    out.copy_from_slice(&full.as_bytes()[..GROUP_SELECTOR_V5_LEN]);\n    out\n}\n\nfn outer_v5_aad(group: &GroupId, selector: &[u8]) -> Vec<u8> {\n    // GroupId is intentionally authenticated but not transmitted. This means\n    // even if two candidate groups somehow share a group key (and therefore a\n    // selector), the wrong candidate fails AEAD and the resolver can continue.\n    let mut aad = Vec::with_capacity(MAGIC_GROUP_MESSAGE_V5.len() + selector.len() + 32);\n    aad.extend_from_slice(MAGIC_GROUP_MESSAGE_V5);\n    aad.extend_from_slice(selector);\n    aad.extend_from_slice(group.as_bytes());\n    aad\n}\n\n/// Current anonymous sender-key outer envelope:\n/// `MAGIC_X05 || nonce(12) || selector(16) || ciphertext`.\nfn seal_outer_v5(\n    group: &GroupId,\n    group_key: &[u8; 32],\n    inner: &[u8],\n) -> Result<Vec<u8>> {\n    let outer_key = derive_outer_v5_key(group_key);\n    let nonce_bytes = secure_rng::random::array::<12>()?;\n    let selector = group_selector_v5(group_key, &nonce_bytes);\n    let cipher = ChaCha20Poly1305::new(&outer_key.into());\n    let ciphertext = cipher\n        .encrypt(\n            Nonce::from_slice(&nonce_bytes),\n            Payload {\n                msg: inner,\n                aad: &outer_v5_aad(group, &selector),\n            },\n        )\n        .map_err(|e| anyhow!("outer v5 seal: {e}"))?;\n\n    let mut out = Vec::with_capacity(\n        MAGIC_GROUP_MESSAGE_V5.len() + 12 + GROUP_SELECTOR_V5_LEN + ciphertext.len(),\n    );\n    out.extend_from_slice(MAGIC_GROUP_MESSAGE_V5);\n    out.extend_from_slice(&nonce_bytes);\n    out.extend_from_slice(&selector);\n    out.extend_from_slice(&ciphertext);\n    Ok(out)\n}\n\n/// Open an anonymous x05 frame by scanning the receiver's group-key candidates.\n/// Selector matches are only a routing hint: AEAD failure continues rather than\n/// aborting, so a collision or duplicated key under a wrong GroupId is safe.\nfn open_outer_v5(\n    wire: &[u8],\n    candidates: impl IntoIterator<Item = (GroupId, [u8; 32])>,\n) -> Result<(GroupId, Vec<u8>)> {\n    let header = MAGIC_GROUP_MESSAGE_V5.len() + 12 + GROUP_SELECTOR_V5_LEN;\n    if wire.len() < header + 16 {\n        bail!("v5 frame too short");\n    }\n    if &wire[..MAGIC_GROUP_MESSAGE_V5.len()] != MAGIC_GROUP_MESSAGE_V5 {\n        bail!("not an x05 sender-key group frame");\n    }\n    let mut offset = MAGIC_GROUP_MESSAGE_V5.len();\n    let mut nonce_bytes = [0u8; 12];\n    nonce_bytes.copy_from_slice(&wire[offset..offset + 12]);\n    offset += 12;\n    let wire_selector = &wire[offset..offset + GROUP_SELECTOR_V5_LEN];\n    offset += GROUP_SELECTOR_V5_LEN;\n    let ciphertext = &wire[offset..];\n\n    for (group, group_key) in candidates {\n        if group_selector_v5(&group_key, &nonce_bytes) != wire_selector {\n            continue;\n        }\n        let outer_key = derive_outer_v5_key(&group_key);\n        let cipher = ChaCha20Poly1305::new(&outer_key.into());\n        match cipher.decrypt(\n            Nonce::from_slice(&nonce_bytes),\n            Payload {\n                msg: ciphertext,\n                aad: &outer_v5_aad(&group, wire_selector),\n            },\n        ) {\n            Ok(inner) => return Ok((group, inner)),\n            Err(_) => continue,\n        }\n    }\n    bail!("outer v5: unknown group / not a member")\n}\n\nfn derive_outer_v3_key(group_key: &[u8; 32]) -> [u8; 32] {\n''',
)

# Clarify legacy outer comment.
replace_once(
    "src/ratchet/sender_keys.rs",
    '''/// `MAGIC || group_id(32) || nonce(12) || outer_ciphertext`. Same\n/// metadata posture as v2: only the group id (already public via the\n/// gossipsub topic) and a nonce are plaintext.\n''',
    '''/// Legacy x03 layout: `MAGIC || group_id(32) || nonce(12) || ciphertext`.\n/// Kept only for receive compatibility; new sends use anonymous x05.\n''',
)

# Tests: helper routes current and migration frames through candidate resolution.
p = Path("src/ratchet/sender_keys.rs")
text = p.read_text()
anchor = '''    fn group() -> GroupId {\n        GroupId::from_bytes([0xAB; 32])\n    }\n'''
if text.count(anchor) != 1:
    raise SystemExit("sender_keys.rs: test group helper anchor drifted")
text = text.replace(
    anchor,
    anchor + '''\n    fn decrypt_for(member: &mut Member, wire: &[u8]) -> Result<(GroupId, IdentityId, Vec<u8>)> {\n        decrypt_sender_key_message_candidates(&mut member.ks, [(group(), GROUP_KEY)], wire)\n    }\n''',
    1,
)

text = text.replace(
    '''    fn v3_magic_is_pinned() {\n        assert_eq!(MAGIC_GROUP_MESSAGE_V3, b"QUBEE_GMS\\x03");\n    }\n''',
    '''    fn sender_key_magics_are_pinned() {\n        assert_eq!(MAGIC_GROUP_MESSAGE_V3, b"QUBEE_GMS\\x03");\n        assert_eq!(MAGIC_GROUP_MESSAGE_V5, b"QUBEE_GMS\\x05");\n        assert_eq!(GROUP_SELECTOR_V5_LEN, 16);\n    }\n''',
    1,
)

# Current sender output + id extraction.
text = text.replace('fn v3_message_id_is_stable_and_frame_derivable()', 'fn sender_key_message_id_is_stable_and_frame_derivable()', 1)
text = text.replace('extract_v3_message_id(&GROUP_KEY, &w1)', 'extract_sender_key_message_id([(g, GROUP_KEY)], &w1)')
text = text.replace('extract_v3_message_id(&GROUP_KEY, &w2)', 'extract_sender_key_message_id([(g, GROUP_KEY)], &w2)')
text = text.replace('extract_v3_message_id(&[0u8; 32], &w1)', 'extract_sender_key_message_id([(g, [0u8; 32])], &w1)')
text = text.replace('extract_v3_message_id(&GROUP_KEY, b"not a frame")', 'extract_sender_key_message_id([(g, GROUP_KEY)], b"not a frame")')

# Replace test decrypt calls that use the canonical test group/key.
text = re.sub(
    r'decrypt_sender_key_message\(&mut ([A-Za-z_][A-Za-z0-9_]*)\.ks, &GROUP_KEY, (&?[A-Za-z_][A-Za-z0-9_]*)\)',
    r'decrypt_for(&mut \1, \2)',
    text,
)
# Wrong-key case needs explicit candidate routing under the right group id.
text = text.replace(
    'decrypt_sender_key_message(&mut b.ks, &[0x99; 32], &w)',
    'decrypt_sender_key_message_candidates(&mut b.ks, [(g, [0x99; 32])], &w)',
)
# Current-path forged frame should use x05, not the legacy wrapper.
text = text.replace('seal_outer_v3(&g, &GROUP_KEY, &inner).unwrap()', 'seal_outer_v5(&g, &GROUP_KEY, &inner).unwrap()')
# Current send detection.
text = text.replace('assert!(is_group_message_v3_frame(&wa));', 'assert!(is_group_message_v5_frame(&wa));')
# x05 wrong key reports unknown candidate rather than x03 outer-open wording.
text = text.replace(
    'assert!(err.to_string().contains("outer"), "{err}");',
    'assert!(err.to_string().contains("unknown group"), "{err}");',
    1,
)

# Insert privacy/migration/collision regression before padding test.
marker = '''    #[test]\n    fn padding_collapses_small_messages_to_one_wire_size() {\n'''
if text.count(marker) != 1:
    raise SystemExit("sender_keys.rs: padding test anchor drifted")
extra = '''    #[test]\n    fn x05_hides_group_id_and_rotates_selector_per_message() {\n        let (mut a, _b, _c) = trio();\n        let g = group();\n        let w1 = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"one").unwrap();\n        let w2 = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"two").unwrap();\n        assert!(is_group_message_v5_frame(&w1));\n        assert!(!w1.windows(32).any(|window| window == g.as_bytes()));\n\n        let ml = MAGIC_GROUP_MESSAGE_V5.len();\n        let s1 = &w1[ml + 12..ml + 12 + GROUP_SELECTOR_V5_LEN];\n        let s2 = &w2[ml + 12..ml + 12 + GROUP_SELECTOR_V5_LEN];\n        assert_ne!(s1, s2, "nonce-salted selectors must not be stable across frames");\n    }\n\n    #[test]\n    fn x03_legacy_receive_remains_compatible_while_sends_use_x05() {\n        let (mut a, mut b, _c) = trio();\n        let g = group();\n        let x05 = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"migration").unwrap();\n        let (_, inner) = open_outer_v5(&x05, [(g, GROUP_KEY)]).unwrap();\n        let x03 = seal_outer_v3(&g, &GROUP_KEY, &inner).unwrap();\n        assert!(is_group_message_v3_frame(&x03));\n        assert!(!is_group_message_v5_frame(&x03));\n        let (gid, sender, plaintext) = decrypt_for(&mut b, &x03).unwrap();\n        assert_eq!((gid, sender, plaintext.as_slice()), (g, a.id, b"migration".as_slice()));\n    }\n\n    #[test]\n    fn x05_continues_after_matching_selector_aead_failure() {\n        let (mut a, _b, _c) = trio();\n        let g = group();\n        let wrong_group = GroupId::from_bytes([0xCC; 32]);\n        let wire = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"collision-safe").unwrap();\n\n        // Same key deliberately makes both candidate selectors match. The first\n        // candidate has the wrong hidden GroupId, so its AEAD AAD must fail; the\n        // resolver must continue and accept the second candidate.\n        let (resolved, inner) = open_outer_v5(\n            &wire,\n            [(wrong_group, GROUP_KEY), (g, GROUP_KEY)],\n        )\n        .unwrap();\n        assert_eq!(resolved, g);\n        let msg: SenderKeyMessage = bounded_bincode_deserialize(&inner).unwrap();\n        assert_eq!(msg.sender_id, a.id);\n    }\n\n'''
text = text.replace(marker, extra + marker, 1)
p.write_text(text)

# ---------------------------------------------------------------------------
# JNI: candidate-based x05/x03 routing; public JNI names stay V3 for ABI/Kotlin
# compatibility during the migration.
# ---------------------------------------------------------------------------
replace_once(
    "src/jni_api.rs",
    '''use crate::ratchet::sender_keys::{\n    create_or_get_own_sender_key, decrypt_sender_key_message, encrypt_sender_key_message,\n    extract_v3_message_id, install_sender_key, own_chain_iteration, peek_v3_group_id,\n    reset_group_sender_state, SenderKeyDistribution,\n};\n''',
    '''use crate::ratchet::sender_keys::{\n    create_or_get_own_sender_key, decrypt_sender_key_message_candidates,\n    encrypt_sender_key_message, extract_sender_key_message_id, install_sender_key,\n    own_chain_iteration, reset_group_sender_state, SenderKeyDistribution,\n};\n''',
)

# Replace nativeExtractV3MessageId's plaintext-group-id dispatch with candidates.
p = Path("src/jni_api.rs")
text = p.read_text()
func_anchor = 'pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeExtractV3MessageId('
fi = text.find(func_anchor)
if fi < 0:
    raise SystemExit("jni_api.rs: nativeExtractV3MessageId missing")
start = text.find('            let group_id = match peek_v3_group_id(&bytes) {', fi)
end = text.find('            let java_str = env', start)
if start < 0 or end < 0:
    raise SystemExit("jni_api.rs: nativeExtractV3MessageId routing anchors drifted")
replacement = '''            let candidates = {\n                let gm_guard = GROUP_MANAGER.lock().unwrap();\n                let gm = gm_guard\n                    .as_ref()\n                    .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;\n                gm.group_key_candidates()\n            };\n            let id = match extract_sender_key_message_id(candidates, &bytes) {\n                Some(id) => id,\n                None => return Ok(std::ptr::null_mut()),\n            };\n'''
text = text[:start] + replacement + text[end:]

# Replace decrypt function's group peek/key lookup and call.
dec_anchor = 'pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptGroupMessageV3('
di = text.find(dec_anchor)
if di < 0:
    raise SystemExit("jni_api.rs: nativeDecryptGroupMessageV3 missing")
start = text.find('            let group_id = peek_v3_group_id(&wire_bytes)', di)
end = text.find('            let mut ks_guard = KEYSTORE.lock().unwrap();', start)
if start < 0 or end < 0:
    raise SystemExit("jni_api.rs: nativeDecryptGroupMessageV3 routing anchors drifted")
replacement = '''            let candidates = {\n                let gm_guard = GROUP_MANAGER.lock().unwrap();\n                let gm = gm_guard\n                    .as_ref()\n                    .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;\n                gm.group_key_candidates()\n            };\n'''
text = text[:start] + replacement + text[end:]
old_call = 'decrypt_sender_key_message(ks, &group_key, &wire_bytes)?'
if text.count(old_call) != 1:
    raise SystemExit(f"jni_api.rs: expected one old sender-key decrypt call, got {text.count(old_call)}")
text = text.replace(
    old_call,
    'decrypt_sender_key_message_candidates(ks, candidates, &wire_bytes)?',
    1,
)
# Docs: JNI symbol name is legacy, wire generation is current x05 with x03 receive.
text = text.replace(
    '/// Encrypt a UTF-8 plaintext for a group over the v3 sender-keys\n/// format (Ratchet Stage 4). Returns the `QUBEE_GMS\\x03` wire frame,',
    '/// Encrypt a UTF-8 plaintext for a group over the sender-keys format\n/// (Ratchet Stage 4). The legacy JNI name says V3, but new sends return\n/// `QUBEE_GMS\\x05`; receivers retain `\\x03` migration support.',
    1,
)
text = text.replace(
    '/// Extract the deterministic 16-byte id of a v3 sender-key group frame',
    '/// Extract the deterministic 16-byte id of an x05/x03 sender-key group frame',
    1,
)
text = text.replace(
    '/// Decrypt an inbound v3 group frame',
    '/// Decrypt an inbound sender-key group frame (x05 current / x03 migration)',
    1,
)
p.write_text(text)

# ---------------------------------------------------------------------------
# Android dispatch/retry: accept x05 current + x03 queued legacy.
# ---------------------------------------------------------------------------
replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''        /// "QUBEE_GMS\\x03" — the Stage 4 sender-keys group frame magic.\n        /// Kept in sync with MAGIC_GROUP_MESSAGE_V3 in\n        /// src/ratchet/sender_keys.rs (pinned in wire_stability).\n        private val GROUP_V3_MAGIC: ByteArray =\n            "QUBEE_GMS".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x03)\n''',
    '''        /// Sender-key group wire migration: x05 is the current anonymous\n        /// route; x03 stays receive/retry compatible for queued old frames.\n        private val GROUP_V3_MAGIC: ByteArray =\n            "QUBEE_GMS".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x03)\n        private val GROUP_V5_MAGIC: ByteArray =\n            "QUBEE_GMS".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x05)\n''',
)

p = Path("app/src/main/java/com/qubee/messenger/service/MessageService.kt")
text = p.read_text()
text = text.replace('isGroupV3Frame(wire)', 'isSenderKeyGroupFrame(wire)')
text = text.replace('isGroupV3Frame(data)', 'isSenderKeyGroupFrame(data)')
text = text.replace('// v3 sender-keys group frame (QUBEE_GMS\\x03).', '// sender-keys group frame (x05 current / x03 migration).')
old_fn = '''    private fun isGroupV3Frame(data: ByteArray): Boolean {\n        if (data.size < GROUP_V3_MAGIC.size) return false\n        for (i in GROUP_V3_MAGIC.indices) {\n            if (data[i] != GROUP_V3_MAGIC[i]) return false\n        }\n        return true\n    }\n'''
new_fn = '''    private fun isSenderKeyGroupFrame(data: ByteArray): Boolean =\n        hasMagic(data, GROUP_V5_MAGIC) || hasMagic(data, GROUP_V3_MAGIC)\n\n    private fun hasMagic(data: ByteArray, magic: ByteArray): Boolean {\n        if (data.size < magic.size) return false\n        for (i in magic.indices) {\n            if (data[i] != magic[i]) return false\n        }\n        return true\n    }\n'''
if text.count(old_fn) != 1:
    raise SystemExit("MessageService.kt: isGroupV3Frame function anchor drifted")
text = text.replace(old_fn, new_fn, 1)
text = text.replace('// v3 group frames belong on their group\'s topic', '// sender-key group frames belong on their group\'s topic')
p.write_text(text)

# QubeeManager docs: preserve method names, describe current wire accurately.
p = Path("app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt")
text = p.read_text()
text = text.replace(
    '''     * Encrypt a group message over the v3 sender-keys format (Ratchet\n     * Stage 4): per-sender forward secrecy instead of the v2 shared\n     * symmetric key. Dark-launched — live group traffic still rides\n     * [nativeSendGroupMessage]'s v2 path until the cutover.\n''',
    '''     * Encrypt a group message over sender keys (Ratchet Stage 4). The\n     * JNI/API name remains V3 for compatibility, but current sends emit\n     * QUBEE_GMS\\x05 with anonymous group routing; x03 is receive-only\n     * during migration.\n''',
    1,
)
text = text.replace('     * Deterministic 16-byte id (32-char hex) of a v3 sender-key group', '     * Deterministic 16-byte id (32-char hex) of a sender-key group', 1)
text = text.replace('     * Decrypt an inbound v3 group frame (Ratchet Stage 4). Returns a', '     * Decrypt an inbound sender-key group frame (x05 current / x03 migration). Returns a', 1)
p.write_text(text)

# ---------------------------------------------------------------------------
# Wire stability + parser/fuzz surface.
# ---------------------------------------------------------------------------
replace_once(
    "tests/wire_stability.rs",
    '''fn group_message_v3_magic_is_pinned() {\n    use qubee_crypto::ratchet::sender_keys::MAGIC_GROUP_MESSAGE_V3;\n    // `\\x03` is the sender-keys wire format (Ratchet Stage 4). It\n    // coexists with `\\x02` through the migration window; a bump here is\n    // a deliberate version change with a migration path.\n    assert_eq!(MAGIC_GROUP_MESSAGE_V3, b"QUBEE_GMS\\x03");\n}\n''',
    '''fn sender_key_group_magics_are_pinned() {\n    use qubee_crypto::ratchet::sender_keys::{\n        GROUP_SELECTOR_V5_LEN, MAGIC_GROUP_MESSAGE_V3, MAGIC_GROUP_MESSAGE_V5,\n    };\n    // x03 remains receive-only for queued legacy sender-key frames. x05 is\n    // the current send format and removes the plaintext GroupId.\n    assert_eq!(MAGIC_GROUP_MESSAGE_V3, b"QUBEE_GMS\\x03");\n    assert_eq!(MAGIC_GROUP_MESSAGE_V5, b"QUBEE_GMS\\x05");\n    assert_eq!(GROUP_SELECTOR_V5_LEN, 16);\n}\n''',
)

# Parser robustness: exercise both legacy and candidate-based current extractor.
p = Path("tests/wire_parser_robustness.rs")
text = p.read_text()
text = text.replace(
    'use qubee_crypto::ratchet::sender_keys::extract_v3_message_id;',
    'use qubee_crypto::ratchet::sender_keys::{extract_sender_key_message_id, extract_v3_message_id};',
    1,
)
text = text.replace(
    '        let _ = extract_v3_message_id(&[0u8; 32], &bytes);',
    '        let _ = extract_v3_message_id(&[0u8; 32], &bytes);\n        let _ = extract_sender_key_message_id(\n            [(GroupId::from_bytes([0u8; 32]), [0u8; 32])],\n            &bytes,\n        );',
    1,
)
p.write_text(text)

# New cargo-fuzz target for the current anonymous sender-key outer parser.
Path("fuzz/fuzz_targets/parse_sender_key_group.rs").write_text('''#![no_main]\n\nuse libfuzzer_sys::fuzz_target;\nuse qubee_crypto::groups::group_manager::GroupId;\nuse qubee_crypto::ratchet::sender_keys::{\n    extract_sender_key_message_id, extract_v3_message_id, is_sender_key_group_frame,\n};\n\nfuzz_target!(|data: &[u8]| {\n    let _ = is_sender_key_group_frame(data);\n    let _ = extract_v3_message_id(&[0u8; 32], data);\n    let _ = extract_sender_key_message_id(\n        [(GroupId::from_bytes([0u8; 32]), [0u8; 32])],\n        data,\n    );\n});\n''')
replace_once(
    "fuzz/Cargo.toml",
    '''[[bin]]\nname = "parse_identity_key"\npath = "fuzz_targets/parse_identity_key.rs"\ntest = false\ndoc = false\nbench = false\n''',
    '''[[bin]]\nname = "parse_identity_key"\npath = "fuzz_targets/parse_identity_key.rs"\ntest = false\ndoc = false\nbench = false\n\n[[bin]]\nname = "parse_sender_key_group"\npath = "fuzz_targets/parse_sender_key_group.rs"\ntest = false\ndoc = false\nbench = false\n''',
)

# ---------------------------------------------------------------------------
# Security/design docs: x05 current, x03 receive-only; no false privacy claim.
# ---------------------------------------------------------------------------
p = Path("SECURITY.md")
text = p.read_text()
text = text.replace(
    'already understands `QUBEE_DMS` / `QUBEE_GMS\\x03` frames, and the',
    'already understands `QUBEE_DMS` and sender-key `QUBEE_GMS\\x05` frames\n  (`\\x03` remains receive-only for queued migration traffic), and the',
    1,
)
text = text.replace(
    '''  topic is a blinded rotating hash instead of the group id in the\n  clear, and the group-message envelope (`QUBEE_GMS\\x04`) replaced its\n  plaintext `group_id` with a per-message keyed selector. Neither the\n  topic nor the payload now names a group, and neither is stable\n  across messages — but note this hides *which* group, not *that*\n  group traffic exists.\n''',
    '''  topic is a blinded rotating hash instead of the group id in the\n  clear. Both current group-message envelopes now use per-message keyed\n  selectors instead of plaintext GroupIds: legacy symmetric traffic uses\n  `QUBEE_GMS\\x04`, while forward-secret sender-key traffic emits\n  `QUBEE_GMS\\x05` with a 128-bit selector. Sender-key `\\x03`, which did\n  expose GroupId, is accepted only to drain queued migration traffic and\n  is no longer emitted. Neither current topic nor current payload names a\n  group, and neither selector is stable across messages — but this hides\n  *which* group, not *that* group traffic exists.\n''',
    1,
)
p.write_text(text)

p = Path("docs/double-ratchet-design.md")
text = p.read_text()
text = text.replace(
    '''  `nativeInstallSenderKeyDistribution`, `nativeEncryptGroupMessageV3`,\n  `nativeDecryptGroupMessageV3`). Per-sender BLAKE3 hash chains\n  (`QUBEE_GMS\\x03`) give in-group forward secrecy; a per-group\n''',
    '''  `nativeInstallSenderKeyDistribution`, `nativeEncryptGroupMessageV3`,\n  `nativeDecryptGroupMessageV3`). Per-sender BLAKE3 hash chains give\n  in-group forward secrecy. Current sends use anonymous-routing\n  `QUBEE_GMS\\x05`; plaintext-GroupId `\\x03` is receive-only during the\n  migration window. A per-group\n''',
    1,
)
text = text.replace('`QUBEE_DMS`/`QUBEE_GMS\\x03` frames unconditionally', '`QUBEE_DMS` and `QUBEE_GMS\\x05`/legacy-`\\x03` frames unconditionally', 1)
text = text.replace(
    '''**Stage 4 (LANDED, dark):** sender-keys group messaging on top of DR —\n`src/ratchet/sender_keys.rs`, wire `QUBEE_GMS\\x03`, JNI dark-launched.\nMigration plan unchanged: existing groups keep the v2 symmetric key for\none release; new groups (and any group after a member-add /\nmember-remove) start on v3. Cleanup batch removes v2 support after a\ndeprecation window.\n''',
    '''**Stage 4 (LANDED, dark):** sender-keys group messaging on top of DR —\n`src/ratchet/sender_keys.rs`, current wire `QUBEE_GMS\\x05`, JNI\ndark-launched. x05 hides GroupId behind a nonce-salted 128-bit keyed\nselector; `QUBEE_GMS\\x03` remains receive-only for queued migration\nframes. Existing groups keep the v2 symmetric key for one release; new\ngroups (and any group after a member-add / member-remove) start on the\nsender-key path. Cleanup removes v2/x03 receive support after the\ndeprecation window.\n''',
    1,
)
p.write_text(text)

print("GMS x05 anonymous sender-key patch applied")
