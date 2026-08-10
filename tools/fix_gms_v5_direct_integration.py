from pathlib import Path

p = Path("src/ratchet/direct.rs")
text = p.read_text()

old_import = '''        use crate::ratchet::sender_keys::{
            create_or_get_own_sender_key, decrypt_sender_key_message, encrypt_sender_key_message,
            install_sender_key,
        };
'''
new_import = '''        use crate::ratchet::sender_keys::{
            create_or_get_own_sender_key, decrypt_sender_key_message_candidates,
            encrypt_sender_key_message, install_sender_key,
        };
'''
if text.count(old_import) != 1:
    raise SystemExit(f"expected one sender-key integration import, found {text.count(old_import)}")
text = text.replace(old_import, new_import, 1)

old_comment = '''        // channel-authenticated sender id, and Alice's next v3 group
        // frame decrypts on Bob's side.
'''
new_comment = '''        // channel-authenticated sender id, and Alice's next current
        // sender-key group frame decrypts on Bob's side through the
        // x05/x03 migration-aware candidate resolver.
'''
if text.count(old_comment) != 1:
    raise SystemExit(f"expected one stale v3 comment, found {text.count(old_comment)}")
text = text.replace(old_comment, new_comment, 1)

old_call = '''        let (gid, from, pt) = decrypt_sender_key_message(&mut b.ks, &group_key, &frame).unwrap();
'''
new_call = '''        let (gid, from, pt) = decrypt_sender_key_message_candidates(
            &mut b.ks,
            [(group, group_key)],
            &frame,
        )
        .unwrap();
'''
if text.count(old_call) != 1:
    raise SystemExit(f"expected one legacy integration decrypt call, found {text.count(old_call)}")
text = text.replace(old_call, new_call, 1)

p.write_text(text)
print("x05 direct integration test fix applied")
