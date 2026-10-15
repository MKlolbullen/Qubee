//! Page-locked scratch memory for secrets that must not be swapped out.
//!
//! `mlock` keeps the pages resident. It does not keep them out of core
//! dumps, and the kernel may refuse it (`RLIMIT_MEMLOCK`); then the
//! allocation fails instead of quietly handing out ordinary heap.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretBox};
use std::alloc::{self, Layout};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroize;

/// Hands out page-locked regions and caps how much locked memory they
/// hold together.
pub struct SecureAllocator {
    allocated_bytes: AtomicUsize,
    max_allocation: usize,
}

impl SecureAllocator {
    const DEFAULT_MAX_ALLOCATION: usize = 64 * 1024 * 1024;

    pub fn new() -> Self {
        Self::with_max_allocation(Self::DEFAULT_MAX_ALLOCATION)
    }

    pub fn with_max_allocation(max_allocation: usize) -> Self {
        Self {
            allocated_bytes: AtomicUsize::new(0),
            max_allocation,
        }
    }

    /// `size` zeroed bytes in freshly locked pages. The region is zeroed
    /// again, unlocked and freed on drop. A refused request, including
    /// one the kernel will not lock, charges nothing to the budget.
    pub fn allocate_secure(&self, size: usize) -> Result<SecureMemoryRegion<'_>> {
        anyhow::ensure!(size > 0, "Cannot allocate zero bytes");
        let page_size = page_size()?;
        let locked_size = size
            .checked_add(page_size - 1)
            .map(|rounded| rounded & !(page_size - 1))
            .context("allocation size overflows")?;
        let layout =
            Layout::from_size_align(locked_size, page_size).context("Invalid memory layout")?;

        // The whole locked span is reserved in one atomic step before
        // anything is allocated, so racing requests cannot both pass the
        // check and the budget is never exceeded.
        self.allocated_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(locked_size)
                    .filter(|&next| next <= self.max_allocation)
            })
            .map_err(|_| anyhow::anyhow!("Allocation would exceed maximum limit"))?;

        let Some(ptr) = NonNull::new(unsafe { alloc::alloc_zeroed(layout) }) else {
            self.release(locked_size);
            return Err(anyhow::anyhow!("Memory allocation failed"));
        };
        if let Err(error) = lock_pages(ptr, locked_size) {
            unsafe { alloc::dealloc(ptr.as_ptr(), layout) };
            self.release(locked_size);
            return Err(error);
        }

        Ok(SecureMemoryRegion {
            ptr,
            locked_size,
            len: size,
            layout,
            allocator: self,
        })
    }

    /// Bytes currently held in locked pages, counted in whole pages.
    pub fn allocated_bytes(&self) -> usize {
        self.allocated_bytes.load(Ordering::Acquire)
    }

    fn release(&self, bytes: usize) {
        self.allocated_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }

    fn deallocate(&self, region: &mut SecureMemoryRegion<'_>) {
        // Volatile writes: a plain memset right before the free is a dead
        // store the optimiser may drop.
        unsafe { std::slice::from_raw_parts_mut(region.ptr.as_ptr(), region.locked_size) }
            .zeroize();
        unlock_pages(region.ptr, region.locked_size);
        unsafe { alloc::dealloc(region.ptr.as_ptr(), region.layout) };
        self.release(region.locked_size);
    }
}

impl Default for SecureAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Bytes in locked pages; zeroed, unlocked and freed on drop.
pub struct SecureMemoryRegion<'a> {
    ptr: NonNull<u8>,
    locked_size: usize,
    len: usize,
    layout: Layout,
    allocator: &'a SecureAllocator,
}

impl SecureMemoryRegion<'_> {
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Drop for SecureMemoryRegion<'_> {
    fn drop(&mut self) {
        let allocator = self.allocator;
        allocator.deallocate(self);
    }
}

#[cfg(unix)]
fn page_size() -> Result<usize> {
    let size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .context("sysconf(_SC_PAGESIZE) failed")?;
    anyhow::ensure!(size.is_power_of_two(), "unusable page size {size}");
    Ok(size)
}

#[cfg(unix)]
fn lock_pages(ptr: NonNull<u8>, len: usize) -> Result<()> {
    let rc = unsafe { libc::mlock(ptr.as_ptr().cast::<libc::c_void>(), len) };
    anyhow::ensure!(
        rc == 0,
        "Failed to lock memory: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[cfg(unix)]
fn unlock_pages(ptr: NonNull<u8>, len: usize) {
    // The pages are freed right after this; a failure leaves nothing to
    // act on.
    let _ = unsafe { libc::munlock(ptr.as_ptr().cast::<libc::c_void>(), len) };
}

#[cfg(not(unix))]
fn page_size() -> Result<usize> {
    anyhow::bail!("page locking is only implemented for unix targets")
}

#[cfg(not(unix))]
fn lock_pages(_ptr: NonNull<u8>, _len: usize) -> Result<()> {
    anyhow::bail!("page locking is only implemented for unix targets")
}

#[cfg(not(unix))]
fn unlock_pages(_ptr: NonNull<u8>, _len: usize) {}

/// A string whose bytes are zeroised when it is dropped.
pub struct SecureString {
    inner: SecretBox<String>,
}

impl SecureString {
    pub fn new(s: String) -> Self {
        SecureString {
            inner: SecretBox::new(Box::new(s)),
        }
    }

    pub fn expose_secret(&self) -> &str {
        self.inner.expose_secret()
    }

    pub fn len(&self) -> usize {
        self.inner.expose_secret().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.expose_secret().is_empty()
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self::new(s.to_owned())
    }
}

static GLOBAL_ALLOCATOR: std::sync::OnceLock<SecureAllocator> = std::sync::OnceLock::new();

pub fn global_allocator() -> &'static SecureAllocator {
    GLOBAL_ALLOCATOR.get_or_init(SecureAllocator::default)
}

pub fn allocate_secure(size: usize) -> Result<SecureMemoryRegion<'static>> {
    global_allocator().allocate_secure(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_region_is_zeroed_and_exactly_as_long_as_requested() {
        let allocator = SecureAllocator::new();
        let region = allocator.allocate_secure(1024).expect("allocate");
        assert_eq!(region.len(), 1024);
        assert!(!region.is_empty());
        assert!(region.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn a_zero_byte_request_is_refused() {
        assert!(SecureAllocator::new().allocate_secure(0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn zeroize_clears_the_region() {
        let allocator = SecureAllocator::new();
        let mut region = allocator.allocate_secure(32).expect("allocate");
        region.as_mut_slice().fill(0xA5);
        region.zeroize();
        assert!(region.as_slice().iter().all(|&b| b == 0));
    }

    #[cfg(unix)]
    #[test]
    fn the_budget_counts_whole_locked_pages() {
        let page = page_size().expect("page size");
        let allocator = SecureAllocator::with_max_allocation(page);
        let one_byte = allocator.allocate_secure(1).expect("fits in one page");
        assert_eq!(allocator.allocated_bytes(), page);
        assert!(allocator.allocate_secure(1).is_err());
        drop(one_byte);
        assert_eq!(allocator.allocated_bytes(), 0);
        assert!(allocator.allocate_secure(page).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_refused_request_charges_nothing() {
        let page = page_size().expect("page size");
        let allocator = SecureAllocator::with_max_allocation(page);
        for size in [page + 1, usize::MAX - page, usize::MAX] {
            assert!(allocator.allocate_secure(size).is_err());
            assert_eq!(allocator.allocated_bytes(), 0);
        }
        assert!(allocator.allocate_secure(page).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn racing_requests_never_exceed_the_budget() {
        let page = page_size().expect("page size");
        let allocator = SecureAllocator::with_max_allocation(4 * page);
        let barrier = std::sync::Barrier::new(16);
        let granted = std::thread::scope(|scope| {
            let attempts: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        let region = allocator.allocate_secure(1);
                        // Hold the page until every thread has tried.
                        barrier.wait();
                        region.is_ok()
                    })
                })
                .collect();
            attempts
                .into_iter()
                .map(|attempt| attempt.join().expect("thread"))
                .filter(|&granted| granted)
                .count()
        });
        assert_eq!(granted, 4);
        assert_eq!(allocator.allocated_bytes(), 0);
    }

    #[test]
    fn secure_string_exposes_its_contents() {
        let secure = SecureString::from("secret password");
        assert_eq!(secure.expose_secret(), "secret password");
        assert_eq!(secure.len(), 15);
        assert!(!secure.is_empty());
    }
}
