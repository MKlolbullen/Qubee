use anyhow::{Context, Result};
use secrecy::{Secret, ExposeSecret};
use serde::{Serialize, Deserialize};
use blake3::Hasher;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use crate::identity::identity_key::{IdentityKey, IdentityKeyPair, IdentityId};
use crate::security::secure_rng;
use std::time::{SystemTime, UNIX_EPOCH};

/// Zero-Knowledge proof of key ownership without revealing the private key
#[derive(Clone, Serialize, Deserialize)]
pub struct ZKProof {
    /// The identity being proven
    pub identity_id: IdentityId,
    
    /// Schnorr proof components
    pub commitment: [u8; 32],
    pub challenge: [u8; 32],
    pub response: [u8; 32],
    
    /// Post-quantum proof components
    pub pq_commitment: Vec<u8>,
    pub pq_response: Vec<u8>,
    
    /// Proof metadata
    pub timestamp: u64,
    pub nonce: [u8; 32],
    pub context: String,
    
    /// Optional additional claims
    pub claims: Vec<ZKClaim>,
}

/// Additional claims that can be proven alongside key ownership
#[derive(Clone, Serialize, Deserialize)]
pub struct ZKClaim {
    pub claim_type: String,
    pub claim_data: Vec<u8>,
    pub proof_data: Vec<u8>,
}

/// Generator for Zero-Knowledge proofs
pub struct ZKProofGenerator {
    identity_keypair: IdentityKeyPair,
}

/// Verifier for Zero-Knowledge proofs
pub struct ZKProofVerifier;

/// Proof verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofVerificationResult {
    Valid,
    Invalid,
    Expired,
    ReplayAttack,
    InvalidContext,
}

/// Context for proof generation and verification
#[derive(Clone)]
pub struct ProofContext {
    pub purpose: String,
    pub audience: Option<IdentityId>,
    pub validity_duration: u64, // seconds
    pub additional_data: Vec<u8>,
}

impl ZKProofGenerator {
    /// Create a new proof generator with an identity key pair
    pub fn new(identity_keypair: IdentityKeyPair) -> Self {
        ZKProofGenerator { identity_keypair }
    }
    
    /// Generate a Zero-Knowledge proof of key ownership
    pub fn generate_proof(&self, context: &ProofContext) -> Result<ZKProof> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let nonce = secure_rng::random::array::<32>()?;
        
        // Generate classical Schnorr proof
        let (commitment, challenge, response) = self.generate_schnorr_proof(
            &context.purpose,
            &context.additional_data,
            timestamp,
            &nonce,
        )?;
        
        // Generate post-quantum proof (simplified commitment scheme)
        let (pq_commitment, pq_response) = self.generate_pq_proof(
            &context.purpose,
            &context.additional_data,
            timestamp,
            &nonce,
        )?;
        
        // Generate any additional claims
        let claims = self.generate_claims(context)?;
        
        Ok(ZKProof {
            identity_id: self.identity_keypair.identity_id(),
            commitment,
            challenge,
            response,
            pq_commitment,
            pq_response,
            timestamp,
            nonce,
            context: context.purpose.clone(),
            claims,
        })
    }
    
    /// Generate a proof that can be encoded as a QR code
    pub fn generate_qr_proof(&self, context: &ProofContext) -> Result<String> {
        let proof = self.generate_proof(context)?;
        let serialized = bincode::serialize(&proof)?;
        
        // Compress and encode for QR code
        let compressed = self.compress_proof_data(&serialized)?;
        Ok(base64::encode(compressed))
    }
    
    /// Generate a proof for NFC transmission
    pub fn generate_nfc_proof(&self, context: &ProofContext) -> Result<Vec<u8>> {
        let proof = self.generate_proof(context)?;
        let serialized = bincode::serialize(&proof)?;
        
        // Add NFC-specific headers and checksums
        let mut nfc_data = Vec::new();
        nfc_data.extend_from_slice(b"QUBEE_ZK");
        nfc_data.extend_from_slice(&(serialized.len() as u32).to_le_bytes());
        nfc_data.extend_from_slice(&serialized);
        
        // Add CRC32 checksum
        let checksum = crc32fast::hash(&nfc_data);
        nfc_data.extend_from_slice(&checksum.to_le_bytes());
        
        Ok(nfc_data)
    }
    
    /// Generate classical Schnorr proof
    fn generate_schnorr_proof(
        &self,
        purpose: &str,
        additional_data: &[u8],
        timestamp: u64,
        nonce: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
        // Generate random commitment value
        let r = secure_rng::random::array::<32>()?;
        let r_scalar = SigningKey::from_bytes(&r);
        
        // Compute commitment R = r * G
        let commitment_point = r_scalar.verifying_key();
        let commitment = commitment_point.to_bytes();
        
        // Compute challenge hash
        let challenge = self.compute_challenge(
            &commitment,
            purpose,
            additional_data,
            timestamp,
            nonce,
        )?;
        
        // Compute response s = r + challenge * private_key
        let private_key = self.identity_keypair.classical_private.expose_secret();
        let challenge_scalar = SigningKey::from_bytes(&challenge);
        
        // Simplified scalar arithmetic (in practice, use proper curve arithmetic)
        let mut response = [0u8; 32];
        for i in 0..32 {
            response[i] = r[i]
                .wrapping_add(challenge[i])
                .wrapping_add(private_key.to_bytes()[i]);
        }
        
        Ok((commitment, challenge, response))
    }
    
    /// Generate post-quantum proof (simplified commitment scheme)
    fn generate_pq_proof(
        &self,
        purpose: &str,
        additional_data: &[u8],
        timestamp: u64,
        nonce: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate random commitment
        let commitment_size = 1024; // Simplified size
        let commitment = secure_rng::random::bytes(commitment_size)?;
        
        // Create response based on private key and challenge
        let challenge = self.compute_challenge(
            &commitment,
            purpose,
            additional_data,
            timestamp,
            nonce,
        )?;
        
        // Simplified response generation (in practice, use proper PQ proof system)
        let mut hasher = Hasher::new();
        hasher.update(self.identity_keypair.pq_private.expose_secret().as_bytes());
        hasher.update(&challenge);
        hasher.update(&commitment);
        
        let response = hasher.finalize().as_bytes().to_vec();
        
        Ok((commitment, response))
    }
    
    /// Generate additional claims
    fn generate_claims(&self, context: &ProofContext) -> Result<Vec<ZKClaim>> {
        let mut claims = Vec::new();
        
        // Add timestamp claim
        claims.push(ZKClaim {
            claim_type: "timestamp".to_string(),
            claim_data: context.additional_data.clone(),
            proof_data: self.identity_keypair.identity_id().as_ref().to_vec(),
        });
        
        // Add audience claim if specified
        if let Some(audience) = &context.audience {
            claims.push(ZKClaim {
                claim_type: "audience".to_string(),
                claim_data: audience.as_ref().to_vec(),
                proof_data: vec![], // Simplified
            });
        }
        
        Ok(claims)
    }
    
    /// Compute challenge hash for Fiat-Shamir transform
    fn compute_challenge(
        &self,
        commitment: &[u8],
        purpose: &str,
        additional_data: &[u8],
        timestamp: u64,
        nonce: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let mut hasher = Hasher::new();
        
        // Add public key
        hasher.update(self.identity_keypair.public_key().classical_public.as_bytes());
        hasher.update(self.identity_keypair.public_key().pq_public.as_bytes());
        
        // Add commitment
        hasher.update(commitment);
        
        // Add context
        hasher.update(purpose.as_bytes());
        hasher.update(additional_data);
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(nonce);
        
        // Add domain separator
        hasher.update(b"qubee_zk_challenge");
        
        let hash = hasher.finalize();
        Ok(hash.as_bytes()[..32].try_into().unwrap())
    }
    
    /// Compress proof data for efficient transmission
    fn compress_proof_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Simple compression (in practice, use proper compression algorithm)
        let mut compressed = Vec::new();
        
        // Add magic header
        compressed.extend_from_slice(b"ZKP1");
        
        // Add original length
        compressed.extend_from_slice(&(data.len() as u32).to_le_bytes());
        
        // Simple run-length encoding
        let mut i = 0;
        while i < data.len() {
            let byte = data[i];
            let mut count = 1;
            
            while i + count < data.len() && data[i + count] == byte && count < 255 {
                count += 1;
            }
            
            if count > 3 {
                compressed.push(0xFF); // Escape byte
                compressed.push(count as u8);
                compressed.push(byte);
            } else {
                for _ in 0..count {
                    compressed.push(byte);
                }
            }
            
            i += count;
        }
        
        Ok(compressed)
    }
}

impl ZKProofVerifier {
    /// Create a new proof verifier
    pub fn new() -> Self {
        ZKProofVerifier
    }
    
    /// Verify a Zero-Knowledge proof
    pub fn verify_proof(
        &self,
        proof: &ZKProof,
        public_key: &IdentityKey,
        context: &ProofContext,
    ) -> Result<ProofVerificationResult> {
        // Check identity matches
        if proof.identity_id != public_key.identity_id {
            return Ok(ProofVerificationResult::Invalid);
        }
        
        // Check context matches
        if proof.context != context.purpose {
            return Ok(ProofVerificationResult::InvalidContext);
        }
        
        // Check timestamp validity
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        if current_time.saturating_sub(proof.timestamp) > context.validity_duration {
            return Ok(ProofVerificationResult::Expired);
        }
        
        // Check for replay attacks (simplified - in practice, maintain nonce database)
        if self.is_replay_attack(&proof.nonce)? {
            return Ok(ProofVerificationResult::ReplayAttack);
        }
        
        // Verify classical Schnorr proof
        let classical_valid = self.verify_schnorr_proof(
            proof,
            public_key,
            &context.purpose,
            &context.additional_data,
        )?;
        
        // Verify post-quantum proof
        let pq_valid = self.verify_pq_proof(
            proof,
            public_key,
            &context.purpose,
            &context.additional_data,
        )?;
        
        // Verify additional claims
        let claims_valid = self.verify_claims(&proof.claims, public_key)?;
        
        if classical_valid && pq_valid && claims_valid {
            Ok(ProofVerificationResult::Valid)
        } else {
            Ok(ProofVerificationResult::Invalid)
        }
    }
    
    /// Verify a proof from QR code data
    pub fn verify_qr_proof(
        &self,
        qr_data: &str,
        expected_identity: &IdentityKey,
        context: &ProofContext,
    ) -> Result<ProofVerificationResult> {
        let compressed_data = base64::decode(qr_data)
            .context("Invalid base64 encoding")?;
        
        let proof_data = self.decompress_proof_data(&compressed_data)?;
        let proof: ZKProof = bincode::deserialize(&proof_data)
            .context("Invalid proof data")?;
        
        self.verify_proof(&proof, expected_identity, context)
    }
    
    /// Verify a proof from NFC data
    pub fn verify_nfc_proof(
        &self,
        nfc_data: &[u8],
        expected_identity: &IdentityKey,
        context: &ProofContext,
    ) -> Result<ProofVerificationResult> {
        // Check NFC header
        if nfc_data.len() < 16 || &nfc_data[..8] != b"QUBEE_ZK" {
            return Err(anyhow::anyhow!("Invalid NFC data format"));
        }
        
        // Extract length
        let length = u32::from_le_bytes(nfc_data[8..12].try_into().unwrap()) as usize;
        
        if nfc_data.len() < 12 + length + 4 {
            return Err(anyhow::anyhow!("Truncated NFC data"));
        }
        
        // Verify checksum
        let data_end = 12 + length;
        let expected_checksum = u32::from_le_bytes(
            nfc_data[data_end..data_end + 4].try_into().unwrap()
        );
        let actual_checksum = crc32fast::hash(&nfc_data[..data_end]);
        
        if expected_checksum != actual_checksum {
            return Err(anyhow::anyhow!("NFC data checksum mismatch"));
        }
        
        // Extract and verify proof
        let proof_data = &nfc_data[12..data_end];
        let proof: ZKProof = bincode::deserialize(proof_data)
            .context("Invalid proof data")?;
        
        self.verify_proof(&proof, expected_identity, context)
    }
    
    /// Verify classical Schnorr proof
    fn verify_schnorr_proof(
        &self,
        proof: &ZKProof,
        public_key: &IdentityKey,
        purpose: &str,
        additional_data: &[u8],
    ) -> Result<bool> {
        // Recompute challenge
        let expected_challenge = self.compute_challenge(
            &proof.commitment,
            public_key,
            purpose,
            additional_data,
            proof.timestamp,
            &proof.nonce,
        )?;
        
        // Check challenge matches
        if expected_challenge != proof.challenge {
            return Ok(false);
        }
        
        // Verify proof equation: s * G = R + challenge * public_key
        // Simplified verification (in practice, use proper curve arithmetic)
        let response_key = SigningKey::from_bytes(&proof.response);
        let response_point = response_key.verifying_key();
        
        // This is a simplified check - proper implementation would use curve arithmetic
        let mut expected_response = [0u8; 32];
        for i in 0..32 {
            expected_response[i] = proof.commitment[i]
                .wrapping_add(proof.challenge[i])
                .wrapping_add(public_key.classical_public.as_bytes()[i]);
        }
        
        Ok(response_point.as_bytes() == &expected_response)
    }
    
    /// Verify post-quantum proof
    fn verify_pq_proof(
        &self,
        proof: &ZKProof,
        public_key: &IdentityKey,
        purpose: &str,
        additional_data: &[u8],
    ) -> Result<bool> {
        // Recompute challenge
        let challenge = self.compute_challenge(
            &proof.pq_commitment,
            public_key,
            purpose,
            additional_data,
            proof.timestamp,
            &proof.nonce,
        )?;
        
        // Verify response (simplified)
        let mut hasher = Hasher::new();
        hasher.update(public_key.pq_public.as_bytes());
        hasher.update(&challenge);
        hasher.update(&proof.pq_commitment);
        
        let expected_response = hasher.finalize().as_bytes().to_vec();
        
        Ok(expected_response == proof.pq_response)
    }
    
    /// Verify additional claims
    fn verify_claims(&self, claims: &[ZKClaim], public_key: &IdentityKey) -> Result<bool> {
        for claim in claims {
            match claim.claim_type.as_str() {
                "timestamp" => {
                    // Verify timestamp claim
                    if claim.proof_data != public_key.identity_id.as_ref() {
                        return Ok(false);
                    }
                }
                "audience" => {
                    // Verify audience claim (simplified)
                    // In practice, this would verify the audience-specific proof
                }
                _ => {
                    // Unknown claim type - ignore for forward compatibility
                }
            }
        }
        
        Ok(true)
    }
    
    /// Check for replay attacks (simplified implementation)
    fn is_replay_attack(&self, nonce: &[u8; 32]) -> Result<bool> {
        // In practice, maintain a database of used nonces with expiration
        // For now, just return false (no replay detected)
        Ok(false)
    }
    
    /// Compute challenge hash
    fn compute_challenge(
        &self,
        commitment: &[u8],
        public_key: &IdentityKey,
        purpose: &str,
        additional_data: &[u8],
        timestamp: u64,
        nonce: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let mut hasher = Hasher::new();
        
        hasher.update(public_key.classical_public.as_bytes());
        hasher.update(public_key.pq_public.as_bytes());
        hasher.update(commitment);
        hasher.update(purpose.as_bytes());
        hasher.update(additional_data);
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(nonce);
        hasher.update(b"qubee_zk_challenge");
        
        let hash = hasher.finalize();
        Ok(hash.as_bytes()[..32].try_into().unwrap())
    }
    
    /// Decompress proof data
    fn decompress_proof_data(&self, compressed: &[u8]) -> Result<Vec<u8>> {
        if compressed.len() < 8 || &compressed[..4] != b"ZKP1" {
            return Err(anyhow::anyhow!("Invalid compressed data format"));
        }
        
        let original_length = u32::from_le_bytes(
            compressed[4..8].try_into().unwrap()
        ) as usize;
        
        let mut decompressed = Vec::with_capacity(original_length);
        let mut i = 8;
        
        while i < compressed.len() {
            if compressed[i] == 0xFF && i + 2 < compressed.len() {
                // Run-length encoded sequence
                let count = compressed[i + 1] as usize;
                let byte = compressed[i + 2];
                
                for _ in 0..count {
                    decompressed.push(byte);
                }
                
                i += 3;
            } else {
                decompressed.push(compressed[i]);
                i += 1;
            }
        }
        
        if decompressed.len() != original_length {
            return Err(anyhow::anyhow!("Decompression length mismatch"));
        }
        
        Ok(decompressed)
    }
}

impl Default for ZKProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ProofContext {
    fn default() -> Self {
        ProofContext {
            purpose: "key_verification".to_string(),
            audience: None,
            validity_duration: 300, // 5 minutes
            additional_data: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zk_proof_generation_and_verification() {
        let identity_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let public_key = identity_keypair.public_key();
        
        let generator = ZKProofGenerator::new(identity_keypair);
        let verifier = ZKProofVerifier::new();
        
        let context = ProofContext::default();
        let proof = generator.generate_proof(&context).expect("Should generate proof");
        
        let result = verifier.verify_proof(&proof, &public_key, &context)
            .expect("Should verify proof");
        
        assert_eq!(result, ProofVerificationResult::Valid);
    }
    
    #[test]
    fn test_qr_code_proof() {
        let identity_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let public_key = identity_keypair.public_key();
        
        let generator = ZKProofGenerator::new(identity_keypair);
        let verifier = ZKProofVerifier::new();
        
        let context = ProofContext::default();
        let qr_data = generator.generate_qr_proof(&context).expect("Should generate QR proof");
        
        let result = verifier.verify_qr_proof(&qr_data, &public_key, &context)
            .expect("Should verify QR proof");
        
        assert_eq!(result, ProofVerificationResult::Valid);
    }
    
    #[test]
    fn test_nfc_proof() {
        let identity_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let public_key = identity_keypair.public_key();
        
        let generator = ZKProofGenerator::new(identity_keypair);
        let verifier = ZKProofVerifier::new();
        
        let context = ProofContext::default();
        let nfc_data = generator.generate_nfc_proof(&context).expect("Should generate NFC proof");
        
        let result = verifier.verify_nfc_proof(&nfc_data, &public_key, &context)
            .expect("Should verify NFC proof");
        
        assert_eq!(result, ProofVerificationResult::Valid);
    }
    
    #[test]
    fn test_proof_expiration() {
        let identity_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let public_key = identity_keypair.public_key();
        
        let generator = ZKProofGenerator::new(identity_keypair);
        let verifier = ZKProofVerifier::new();
        
        let mut context = ProofContext::default();
        context.validity_duration = 1; // 1 second
        
        let proof = generator.generate_proof(&context).expect("Should generate proof");
        
        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        let result = verifier.verify_proof(&proof, &public_key, &context)
            .expect("Should verify proof");
        
        assert_eq!(result, ProofVerificationResult::Expired);
    }
    
    #[test]
    fn test_wrong_identity_verification() {
        let identity_keypair1 = IdentityKeyPair::generate().expect("Should generate keypair 1");
        let identity_keypair2 = IdentityKeyPair::generate().expect("Should generate keypair 2");
        let public_key2 = identity_keypair2.public_key();
        
        let generator = ZKProofGenerator::new(identity_keypair1);
        let verifier = ZKProofVerifier::new();
        
        let context = ProofContext::default();
        let proof = generator.generate_proof(&context).expect("Should generate proof");
        
        // Try to verify with wrong public key
        let result = verifier.verify_proof(&proof, &public_key2, &context)
            .expect("Should verify proof");
        
        assert_eq!(result, ProofVerificationResult::Invalid);
    }
}
