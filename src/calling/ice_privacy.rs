//! Defense in depth for relay-only ICE signaling. The transport policy in
//! WebRTC must also be Relay; filtering signaling alone cannot prevent a
//! direct connectivity check or a direct libp2p signaling connection.

use anyhow::{bail, Result};

/// Validate the actual candidate type and remove optional related-address
/// attributes, which may otherwise expose a private/reflexive address even
/// when the candidate itself is a TURN allocation.
pub fn relay_candidate(candidate: &str) -> Result<String> {
    let fields: Vec<&str> = candidate.split_whitespace().collect();
    let type_index = fields
        .iter()
        .position(|field| *field == "typ")
        .ok_or_else(|| anyhow::anyhow!("ICE candidate has no type"))?;
    if fields.get(type_index + 1) != Some(&"relay") || type_index < 6 {
        bail!("only relay ICE candidates are permitted");
    }
    let mut sanitized = Vec::with_capacity(fields.len());
    let mut i = 0;
    while i < fields.len() {
        if fields[i] == "raddr" || fields[i] == "rport" {
            if i + 1 >= fields.len() {
                bail!("incomplete ICE related-address attribute");
            }
            i += 2;
        } else {
            sanitized.push(fields[i]);
            i += 1;
        }
    }
    Ok(sanitized.join(" "))
}

/// Inspect all inline candidates in an SDP offer/answer. Non-relay lines
/// abort the negotiation; silently dropping one risks a misleading SDP.
pub fn relay_sdp(sdp: &str) -> Result<String> {
    let mut result = String::with_capacity(sdp.len());
    for line in sdp.lines() {
        if line.starts_with("a=remote-candidates:") {
            bail!("remote-candidates attribute is not allowed in relay SDP");
        }
        if let Some(candidate) = line.strip_prefix("a=candidate:") {
            result.push_str("a=candidate:");
            result.push_str(&relay_candidate(candidate)?);
        } else {
            result.push_str(line.trim_end_matches('\r'));
        }
        result.push_str("\r\n");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: &str =
        "candidate:1 1 udp 1 203.0.113.10 443 typ relay raddr 192.168.1.2 rport 5151 generation 0";

    #[test]
    fn relay_only_scrubs_related_address_and_rejects_direct_candidates() {
        let safe = relay_candidate(RELAY).unwrap();
        assert!(safe.contains("typ relay"));
        assert!(!safe.contains("192.168.1.2"));
        assert!(!safe.contains("5151"));
        assert!(relay_candidate("candidate:1 1 udp 1 192.168.1.2 5 typ host").is_err());
        assert!(relay_candidate("candidate:1 1 udp 1 203.0.113.2 5 typ srflx").is_err());
        assert!(relay_candidate("candidate:1 1 udp 1 203.0.113.2 5 xtyp relay").is_err());
    }

    #[test]
    fn inline_sdp_candidates_obey_the_same_rule() {
        let sdp = format!("v=0\r\na={RELAY}\r\n");
        let safe = relay_sdp(&sdp).unwrap();
        assert!(!safe.contains("192.168.1.2"));
        assert!(relay_sdp("v=0\r\na=candidate:1 1 udp 1 192.168.1.2 5 typ host\r\n").is_err());
    }
}
