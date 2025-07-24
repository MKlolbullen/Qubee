use anyhow::{Context, Result};
use secrecy::{Secret, ExposeSecret, Zeroize};
use zeroize::ZeroizeOnDrop;
use std::alloc::{self, Layout};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Secure memory allocator that provides protected memory regions
/// for storing sensitive cryptographic material
pub struct SecureAllocator {
    allocated_bytes: AtomicUsize,
    max_allocation: usize,
}

impl SecureAllocator {
    const DEFAULT_MAX_ALLOCATION: usize = 64 * 1024 * 1024; // 64MB
    
    pub fn new() -> Self {
        Self {
            allocated_bytes: AtomicUsize::new(0),
            max_allocation: Self::DEFAULT_MAX_ALLOCATION,
        }
    }
    
    pub fn with_max_allocation(max_allocation: usize) -> Self {
        Self {
            allocated_bytes: AtomicUsize::new(0),
            max_allocation,
        }
    }
    
    /// Allocate secure memory with protection against swapping and core dumps
    pub fn allocate_secure(&self, size: usize) -> Result<SecureMemoryRegion> {
        if size == 0 {
            return Err(anyhow::anyhow!("Cannot allocate zero bytes"));
        }
        
        // Check allocation limits
        let current = self.allocated_bytes.load(Ordering::Acquire);
        if current + size > self.max_allocation {
            return Err(anyhow::anyhow!("Allocation would exceed maximum limit"));
        }
        
        // Align size to page boundary for mlock
        let page_size = Self::get_page_size();
        let aligned_size = (size + page_size - 1) & !(page_size - 1);
        
        // Allocate memory
        let layout = Layout::from_size_align(aligned_size, page_size)
            .context("Invalid memory layout")?;
        
        let ptr = unsafe { alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(anyhow::anyhow!("Memory allocation failed"));
        }
        
        let non_null_ptr = NonNull::new(ptr)
            .ok_or_else(|| anyhow::anyhow!("Allocated null pointer"))?;
        
        // Lock memory to prevent swapping
        #[cfg(unix)]
        {
            let result = unsafe { libc::mlock(ptr as *const libc::c_void, aligned_size) };
            if result != 0 {
                unsafe { alloc::dealloc(ptr, layout) };
                return Err(anyhow::anyhow!("Failed to lock memory: {}", 
                    std::io::Error::last_os_error()));
            }
        }
        
        #[cfg(windows)]
        {
            use winapi::um::memoryapi::VirtualLock;
            let result = unsafe { VirtualLock(ptr as *mut winapi::ctypes::c_void, aligned_size) };
            if result == 0 {
                unsafe { alloc::dealloc(ptr, layout) };
                return Err(anyhow::anyhow!("Failed to lock memory: {}", 
                    std::io::Error::last_os_error()));
            }
        }
        
        // Update allocation counter
        self.allocated_bytes.fetch_add(aligned_size, Ordering::AcqRel);
        
        Ok(SecureMemoryRegion {
            ptr: non_null_ptr,
            size: aligned_size,
            actual_size: size,
            layout,
            allocator: self,
        })
    }
    
    fn get_page_size() -> usize {
        #[cfg(unix)]
        {
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
        }
        
        #[cfg(windows)]
        {
            use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
            let mut sys_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
            unsafe { GetSystemInfo(&mut sys_info) };
            sys_info.dwPageSize as usize
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            4096 // Default page size
        }
    }
    
    fn deallocate(&self, region: &SecureMemoryRegion) {
        // Unlock memory
        #[cfg(unix)]
        {
            unsafe { libc::munlock(region.ptr.as_ptr() as *const libc::c_void, region.size) };
        }
        
        #[cfg(windows)]
        {
            use winapi::um::memoryapi::VirtualUnlock;
            unsafe { VirtualUnlock(region.ptr.as_ptr() as *mut winapi::ctypes::c_void, region.size) };
        }
        
        // Securely zero memory before deallocation
        unsafe {
            std::ptr::write_bytes(region.ptr.as_ptr(), 0, region.size);
        }
        
        // Deallocate memory
        unsafe { alloc::dealloc(region.ptr.as_ptr(), region.layout) };
        
        // Update allocation counter
        self.allocated_bytes.fetch_sub(region.size, Ordering::AcqRel);
    }
}

impl Default for SecureAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// A secure memory region that automatically zeros its contents on drop
pub struct SecureMemoryRegion<'a> {
    ptr: NonNull<u8>,
    size: usize,
    actual_size: usize,
    layout: Layout,
    allocator: &'a SecureAllocator,
}

impl<'a> SecureMemoryRegion<'a> {
    /// Get a mutable slice to the secure memory
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.actual_size) }
    }
    
    /// Get an immutable slice to the secure memory
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.actual_size) }
    }
    
    /// Get the size of the usable memory
    pub fn len(&self) -> usize {
        self.actual_size
    }
    
    /// Check if the memory region is empty
    pub fn is_empty(&self) -> bool {
        self.actual_size == 0
    }
    
    /// Securely zero the memory contents
    pub fn zeroize(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.ptr.as_ptr(), 0, self.actual_size);
        }
    }
}

impl<'a> Drop for SecureMemoryRegion<'a> {
    fn drop(&mut self) {
        self.allocator.deallocate(self);
    }
}

/// A secure buffer that automatically manages its memory
#[derive(ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
    #[zeroize(skip)]
    is_locked: bool,
}

impl SecureBuffer {
    /// Create a new secure buffer with the specified capacity
    pub fn new(capacity: usize) -> Result<Self> {
        let mut data = Vec::with_capacity(capacity);
        
        // Try to lock the memory
        let is_locked = Self::lock_memory(&data);
        
        Ok(SecureBuffer { data, is_locked })
    }
    
    /// Create a secure buffer from existing data
    pub fn from_vec(mut data: Vec<u8>) -> Self {
        let is_locked = Self::lock_memory(&data);
        SecureBuffer { data, is_locked }
    }
    
    /// Get the data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    /// Get the data as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    /// Extend the buffer with additional data
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.data.extend_from_slice(other);
    }
    
    /// Clear the buffer and zeroize its contents
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }
    
    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    fn lock_memory(data: &Vec<u8>) -> bool {
        if data.capacity() == 0 {
            return false;
        }
        
        #[cfg(unix)]
        {
            let result = unsafe {
                libc::mlock(
                    data.as_ptr() as *const libc::c_void,
                    data.capacity(),
                )
            };
            result == 0
        }
        
        #[cfg(windows)]
        {
            use winapi::um::memoryapi::VirtualLock;
            let result = unsafe {
                VirtualLock(
                    data.as_ptr() as *mut winapi::ctypes::c_void,
                    data.capacity(),
                )
            };
            result != 0
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        if self.is_locked && !self.data.is_empty() {
            #[cfg(unix)]
            {
                unsafe {
                    libc::munlock(
                        self.data.as_ptr() as *const libc::c_void,
                        self.data.capacity(),
                    );
                }
            }
            
            #[cfg(windows)]
            {
                use winapi::um::memoryapi::VirtualUnlock;
                unsafe {
                    VirtualUnlock(
                        self.data.as_ptr() as *mut winapi::ctypes::c_void,
                        self.data.capacity(),
                    );
                }
            }
        }
    }
}

/// A secure string that zeroizes its contents on drop
#[derive(ZeroizeOnDrop)]
pub struct SecureString {
    #[zeroize(skip)]
    inner: Secret<String>,
}

impl SecureString {
    /// Create a new secure string
    pub fn new(s: String) -> Self {
        SecureString {
            inner: Secret::new(s),
        }
    }
    
    /// Create a secure string from a str
    pub fn from_str(s: &str) -> Self {
        SecureString {
            inner: Secret::new(s.to_string()),
        }
    }
    
    /// Expose the string contents (use carefully)
    pub fn expose_secret(&self) -> &str {
        self.inner.expose_secret()
    }
    
    /// Get the length of the string
    pub fn len(&self) -> usize {
        self.inner.expose_secret().len()
    }
    
    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.inner.expose_secret().is_empty()
    }
}

/// Global secure allocator instance
static GLOBAL_ALLOCATOR: std::sync::OnceLock<SecureAllocator> = std::sync::OnceLock::new();

/// Get the global secure allocator
pub fn global_allocator() -> &'static SecureAllocator {
    GLOBAL_ALLOCATOR.get_or_init(SecureAllocator::default)
}

/// Allocate secure memory using the global allocator
pub fn allocate_secure(size: usize) -> Result<SecureMemoryRegion<'static>> {
    global_allocator().allocate_secure(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_allocator() {
        let allocator = SecureAllocator::new();
        let region = allocator.allocate_secure(1024).expect("Should allocate");
        assert_eq!(region.len(), 1024);
    }
    
    #[test]
    fn test_secure_buffer() {
        let mut buffer = SecureBuffer::new(1024).expect("Should create buffer");
        buffer.extend_from_slice(b"test data");
        assert_eq!(buffer.as_slice(), b"test data");
        
        buffer.clear();
        assert!(buffer.is_empty());
    }
    
    #[test]
    fn test_secure_string() {
        let secure_str = SecureString::from_str("secret password");
        assert_eq!(secure_str.expose_secret(), "secret password");
        assert_eq!(secure_str.len(), 15);
    }
    
    #[test]
    fn test_memory_region_zeroization() {
        let allocator = SecureAllocator::new();
        let mut region = allocator.allocate_secure(32).expect("Should allocate");
        
        // Write some data
        region.as_mut_slice().copy_from_slice(b"sensitive data that should be zero");
        
        // Manually zeroize
        region.zeroize();
        
        // Check that data is zeroed
        assert!(region.as_slice().iter().all(|&b| b == 0));
    }
    
    #[test]
    fn test_allocation_limits() {
        let allocator = SecureAllocator::with_max_allocation(1024);
        
        // Should succeed
        let _region1 = allocator.allocate_secure(512).expect("Should allocate");
        
        // Should succeed
        let _region2 = allocator.allocate_secure(512).expect("Should allocate");
        
        // Should fail due to limit
        let result = allocator.allocate_secure(1);
        assert!(result.is_err());
    }
}
