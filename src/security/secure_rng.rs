use anyhow::{Context, Result};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use getrandom::getrandom;
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use blake3::Hasher;

/// Enhanced secure random number generator with multiple entropy sources
/// and protection against various attacks
#[derive(ZeroizeOnDrop)]
pub struct SecureRng {
    rng: ChaCha20Rng,
    entropy_pool: [u8; 64],
    reseed_counter: u64,
    last_reseed: u64,
}

impl SecureRng {
    const RESEED_THRESHOLD: u64 = 1_000_000; // Reseed after 1M bytes
    const RESEED_TIME_THRESHOLD: u64 = 3600; // Reseed after 1 hour
    
    /// Create a new secure RNG with enhanced entropy collection
    pub fn new() -> Result<Self> {
        let mut seed = [0u8; 32];
        Self::collect_high_quality_entropy(&mut seed)?;
        
        let mut entropy_pool = [0u8; 64];
        Self::collect_additional_entropy(&mut entropy_pool)?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        Ok(SecureRng {
            rng: ChaCha20Rng::from_seed(seed),
            entropy_pool,
            reseed_counter: 0,
            last_reseed: current_time,
        })
    }
    
    /// Generate random bytes with automatic reseeding
    pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        // Check if reseeding is needed
        if self.should_reseed()? {
            self.reseed()?;
        }
        
        self.rng.fill_bytes(dest);
        self.reseed_counter += dest.len() as u64;
        
        Ok(())
    }
    
    /// Generate a random u64
    pub fn next_u64(&mut self) -> Result<u64> {
        if self.should_reseed()? {
            self.reseed()?;
        }
        
        self.reseed_counter += 8;
        Ok(self.rng.next_u64())
    }
    
    /// Generate a random u32
    pub fn next_u32(&mut self) -> Result<u32> {
        if self.should_reseed()? {
            self.reseed()?;
        }
        
        self.reseed_counter += 4;
        Ok(self.rng.next_u32())
    }
    
    /// Force a reseed operation
    pub fn reseed(&mut self) -> Result<()> {
        let mut new_seed = [0u8; 32];
        Self::collect_high_quality_entropy(&mut new_seed)?;
        
        // Mix with current state for forward security
        let mut hasher = Hasher::new();
        hasher.update(&new_seed);
        hasher.update(&self.entropy_pool);
        hasher.update(&self.reseed_counter.to_le_bytes());
        
        let hash = hasher.finalize();
        new_seed.copy_from_slice(&hash.as_bytes()[..32]);
        
        self.rng = ChaCha20Rng::from_seed(new_seed);
        Self::collect_additional_entropy(&mut self.entropy_pool)?;
        
        self.reseed_counter = 0;
        self.last_reseed = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        // Zeroize the seed
        new_seed.zeroize();
        
        Ok(())
    }
    
    /// Check if reseeding is needed based on usage or time
    fn should_reseed(&self) -> Result<bool> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        Ok(self.reseed_counter >= Self::RESEED_THRESHOLD ||
           current_time - self.last_reseed >= Self::RESEED_TIME_THRESHOLD)
    }
    
    /// Collect high-quality entropy from multiple sources
    fn collect_high_quality_entropy(buffer: &mut [u8; 32]) -> Result<()> {
        // Primary entropy from OS
        getrandom(buffer)
            .context("Failed to get entropy from OS")?;
        
        // Additional entropy mixing
        let mut hasher = Hasher::new();
        hasher.update(buffer);
        
        // Add timing entropy
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            std::hint::black_box(std::time::Instant::now());
        }
        let timing = start.elapsed().as_nanos();
        hasher.update(&timing.to_le_bytes());
        
        // Add process-specific entropy
        hasher.update(&std::process::id().to_le_bytes());
        
        // Add thread-specific entropy
        hasher.update(&std::thread::current().id().as_u64().to_le_bytes());
        
        // Add memory address entropy (ASLR)
        let stack_addr = &buffer as *const _ as usize;
        hasher.update(&stack_addr.to_le_bytes());
        
        #[cfg(unix)]
        {
            // Add Unix-specific entropy
            use std::os::unix::process::CommandExt;
            let pid = unsafe { libc::getpid() };
            hasher.update(&pid.to_le_bytes());
        }
        
        #[cfg(windows)]
        {
            // Add Windows-specific entropy
            use winapi::um::processthreadsapi::GetCurrentProcessId;
            let pid = unsafe { GetCurrentProcessId() };
            hasher.update(&pid.to_le_bytes());
        }
        
        let hash = hasher.finalize();
        buffer.copy_from_slice(&hash.as_bytes()[..32]);
        
        Ok(())
    }
    
    /// Collect additional entropy for the entropy pool
    fn collect_additional_entropy(buffer: &mut [u8; 64]) -> Result<()> {
        let mut hasher = Hasher::new();
        
        // System time with high precision
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?;
        hasher.update(&now.as_nanos().to_le_bytes());
        
        // CPU cycle counter (if available)
        #[cfg(target_arch = "x86_64")]
        {
            let cycles = unsafe { std::arch::x86_64::_rdtsc() };
            hasher.update(&cycles.to_le_bytes());
        }
        
        // Memory allocation patterns
        for _ in 0..10 {
            let vec: Vec<u8> = Vec::with_capacity(1024);
            let addr = vec.as_ptr() as usize;
            hasher.update(&addr.to_le_bytes());
        }
        
        // File system entropy (if available)
        if let Ok(temp_dir) = std::env::temp_dir().read_dir() {
            for entry in temp_dir.take(5) {
                if let Ok(entry) = entry {
                    if let Ok(metadata) = entry.metadata() {
                        hasher.update(&metadata.len().to_le_bytes());
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
                                hasher.update(&duration.as_nanos().to_le_bytes());
                            }
                        }
                    }
                }
            }
        }
        
        let hash = hasher.finalize();
        buffer.copy_from_slice(hash.as_bytes());
        
        Ok(())
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new().expect("Failed to initialize secure RNG")
    }
}

/// Thread-safe global secure RNG instance
pub struct GlobalSecureRng {
    rng: Arc<Mutex<SecureRng>>,
}

impl GlobalSecureRng {
    /// Get the global secure RNG instance
    pub fn instance() -> &'static GlobalSecureRng {
        static INSTANCE: std::sync::OnceLock<GlobalSecureRng> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(|| {
            GlobalSecureRng {
                rng: Arc::new(Mutex::new(SecureRng::new().expect("Failed to initialize global RNG"))),
            }
        })
    }
    
    /// Generate random bytes using the global RNG
    pub fn fill_bytes(&self, dest: &mut [u8]) -> Result<()> {
        let mut rng = self.rng.lock()
            .map_err(|_| anyhow::anyhow!("RNG mutex poisoned"))?;
        rng.fill_bytes(dest)
    }
    
    /// Generate a random u64 using the global RNG
    pub fn next_u64(&self) -> Result<u64> {
        let mut rng = self.rng.lock()
            .map_err(|_| anyhow::anyhow!("RNG mutex poisoned"))?;
        rng.next_u64()
    }
    
    /// Force a reseed of the global RNG
    pub fn reseed(&self) -> Result<()> {
        let mut rng = self.rng.lock()
            .map_err(|_| anyhow::anyhow!("RNG mutex poisoned"))?;
        rng.reseed()
    }
}

/// Convenience functions for common random operations
pub mod random {
    use super::*;
    
    /// Generate random bytes
    pub fn bytes(len: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; len];
        GlobalSecureRng::instance().fill_bytes(&mut buffer)?;
        Ok(buffer)
    }
    
    /// Generate a random array of specified size
    pub fn array<const N: usize>() -> Result<[u8; N]> {
        let mut array = [0u8; N];
        GlobalSecureRng::instance().fill_bytes(&mut array)?;
        Ok(array)
    }
    
    /// Generate a random u64
    pub fn u64() -> Result<u64> {
        GlobalSecureRng::instance().next_u64()
    }
    
    /// Generate a random u32
    pub fn u32() -> Result<u32> {
        Ok((GlobalSecureRng::instance().next_u64()? >> 32) as u32)
    }
    
    /// Generate a random boolean
    pub fn bool() -> Result<bool> {
        Ok(GlobalSecureRng::instance().next_u64()? & 1 == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    
    #[test]
    fn test_secure_rng_creation() {
        let _rng = SecureRng::new().expect("Should create RNG");
    }
    
    #[test]
    fn test_random_bytes_generation() {
        let mut rng = SecureRng::new().expect("Should create RNG");
        let mut buffer = [0u8; 32];
        rng.fill_bytes(&mut buffer).expect("Should generate bytes");
        
        // Check that not all bytes are zero (extremely unlikely)
        assert!(buffer.iter().any(|&b| b != 0));
    }
    
    #[test]
    fn test_random_uniqueness() {
        let mut rng = SecureRng::new().expect("Should create RNG");
        let mut values = HashSet::new();
        
        // Generate 1000 random u64 values
        for _ in 0..1000 {
            let value = rng.next_u64().expect("Should generate u64");
            values.insert(value);
        }
        
        // Should have close to 1000 unique values
        assert!(values.len() > 990);
    }
    
    #[test]
    fn test_reseed_functionality() {
        let mut rng = SecureRng::new().expect("Should create RNG");
        
        // Force a reseed
        rng.reseed().expect("Should reseed successfully");
        
        // Should still generate random numbers
        let value = rng.next_u64().expect("Should generate after reseed");
        assert!(value != 0); // Extremely unlikely to be zero
    }
    
    #[test]
    fn test_global_rng() {
        let global_rng = GlobalSecureRng::instance();
        
        let mut buffer = [0u8; 16];
        global_rng.fill_bytes(&mut buffer).expect("Should generate bytes");
        
        assert!(buffer.iter().any(|&b| b != 0));
    }
    
    #[test]
    fn test_convenience_functions() {
        let bytes = random::bytes(32).expect("Should generate bytes");
        assert_eq!(bytes.len(), 32);
        
        let array = random::array::<16>().expect("Should generate array");
        assert_eq!(array.len(), 16);
        
        let _value = random::u64().expect("Should generate u64");
        let _value = random::u32().expect("Should generate u32");
        let _value = random::bool().expect("Should generate bool");
    }
}
