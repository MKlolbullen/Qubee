//! Bounded queue for real-time media.
//!
//! A full queue drops the oldest item and keeps the newest. That is the
//! opposite of a delivery queue: a slow decoder or a hostile producer must
//! not grow memory or play speech that is seconds late.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

struct Inner<T> {
    items: Mutex<VecDeque<T>>,
    capacity: usize,
    notify: Notify,
    closed: AtomicBool,
    senders: AtomicUsize,
    dropped: AtomicU64,
}

/// Producer half. Cloning increments the sender count; the queue closes
/// when the last sender drops.
pub struct RealtimeSender<T> {
    inner: Arc<Inner<T>>,
}

/// Consumer half. Dropping it closes the queue so producers stop pushing.
pub struct RealtimeReceiver<T> {
    inner: Arc<Inner<T>>,
}

/// Builds a sender/receiver pair sharing a ring buffer of at least size 1.
pub fn realtime_channel<T>(capacity: usize) -> (RealtimeSender<T>, RealtimeReceiver<T>) {
    let capacity = capacity.max(1);
    let inner = Arc::new(Inner {
        items: Mutex::new(VecDeque::with_capacity(capacity)),
        capacity,
        notify: Notify::new(),
        closed: AtomicBool::new(false),
        senders: AtomicUsize::new(1),
        dropped: AtomicU64::new(0),
    });
    (
        RealtimeSender {
            inner: inner.clone(),
        },
        RealtimeReceiver { inner },
    )
}

impl<T> Clone for RealtimeSender<T> {
    /// Registers another live sender so the queue doesn't close until all clones drop.
    fn clone(&self) -> Self {
        self.inner.senders.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Drop for RealtimeSender<T> {
    /// Closes the queue and wakes the receiver once the last sender clone is gone.
    fn drop(&mut self) {
        if self.inner.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.closed.store(true, Ordering::Release);
            self.inner.notify.notify_waiters();
        }
    }
}

impl<T> Drop for RealtimeReceiver<T> {
    /// Closes the queue so any remaining sender stops pushing into a dead consumer.
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }
}

/// Locks `mutex`, recovering the guard on poison instead of propagating the panic.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl<T> RealtimeSender<T> {
    /// Enqueue `item`, dropping the oldest queued item when full.
    /// Returns false if the consumer is gone.
    pub fn push_freshest(&self, item: T) -> bool {
        if self.inner.closed.load(Ordering::Acquire) {
            return false;
        }
        {
            let mut queue = lock(&self.inner.items);
            if self.inner.closed.load(Ordering::Acquire) {
                return false;
            }
            if queue.len() >= self.inner.capacity {
                queue.pop_front();
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            }
            queue.push_back(item);
        }
        self.inner.notify.notify_one();
        true
    }

    /// Total number of items evicted so far because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }
}

impl<T> RealtimeReceiver<T> {
    /// Pops the oldest queued item without waiting, if one is present.
    pub fn try_recv(&mut self) -> Option<T> {
        lock(&self.inner.items).pop_front()
    }

    /// Waits for the next item, returning `None` once the queue is closed and drained.
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            {
                let mut queue = lock(&self.inner.items);
                if let Some(item) = queue.pop_front() {
                    return Some(item);
                }
                if self.inner.closed.load(Ordering::Acquire) {
                    return None;
                }
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sustained_overproduction_keeps_only_the_newest_window() {
        let (tx, mut rx) = realtime_channel::<u16>(12);
        for i in 0..1_000 {
            assert!(tx.push_freshest(i));
        }
        assert!(tx.dropped() >= 1_000 - 12);
        let mut got = Vec::new();
        while let Some(item) = rx.try_recv() {
            got.push(item);
        }
        assert_eq!(got.len(), 12);
        assert_eq!(got, (988..1_000).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn recv_returns_none_after_the_last_sender_drops() {
        let (tx, mut rx) = realtime_channel::<u8>(2);
        tx.push_freshest(7);
        drop(tx);
        assert_eq!(rx.recv().await, Some(7));
        assert_eq!(rx.recv().await, None);
    }
}
