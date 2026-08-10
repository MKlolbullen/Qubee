from pathlib import Path

p = Path("src/ratchet/sender_keys.rs")
text = p.read_text()

old = "            let (gid, sender, pt) = decrypt_for(&mut m, &wa).unwrap();\n"
if text.count(old) != 1:
    raise SystemExit(f"expected one double mutable-borrow test call, found {text.count(old)}")
text = text.replace(
    old,
    "            let (gid, sender, pt) = decrypt_for(m, &wa).unwrap();\n",
    1,
)

old = "fn seal_outer_v3(group: &GroupId, group_key: &[u8; 32], inner: &[u8]) -> Result<Vec<u8>> {\n"
if text.count(old) != 1:
    raise SystemExit(f"expected one legacy x03 sealer, found {text.count(old)}")
text = text.replace(
    old,
    "#[cfg(test)]\nfn seal_outer_v3(group: &GroupId, group_key: &[u8; 32], inner: &[u8]) -> Result<Vec<u8>> {\n",
    1,
)

p.write_text(text)
print("x05 test compile fix applied")
