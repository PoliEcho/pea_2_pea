use pea_2_pea::*;
use std::sync::{Arc, atomic::Ordering};

#[derive(Clone)]
#[readonly::make]
pub struct Client {
    #[readonly]
    pub client_sock_addr: Vec<u8>,
    pub last_heart_beat: i64,
    #[readonly]
    pub iv: [u8; SALT_AND_IV_SIZE as usize],
}

impl Client {
    pub fn new(client_addr: Vec<u8>, heart_beat: i64, iv: [u8; SALT_AND_IV_SIZE as usize]) -> Self {
        Client {
            client_sock_addr: client_addr,
            last_heart_beat: heart_beat,
            iv,
        }
    }
}
#[derive(Clone)]
#[readonly::make]
pub struct Registration {
    #[readonly]
    pub net_id: String,
    #[readonly]
    pub clients: Vec<Client>,

    pub last_heart_beat: i64,

    #[readonly]
    pub encrypted: bool,
    #[readonly]
    pub salt: [u8; SALT_AND_IV_SIZE as usize],
}

impl Registration {
    pub fn new(
        net_id: String,
        client_addr: Vec<u8>,
        encrypted: bool,
        heart_beat: i64,
        salt: Option<[u8; SALT_AND_IV_SIZE as usize]>,
        iv: Option<[u8; SALT_AND_IV_SIZE as usize]>,
    ) -> Self {
        Registration {
            net_id,
            clients: vec![Client::new(
                client_addr,
                heart_beat,
                iv.unwrap_or([0; SALT_AND_IV_SIZE as usize]),
            )],
            encrypted,
            last_heart_beat: heart_beat,
            salt: salt.unwrap_or([0; SALT_AND_IV_SIZE as usize]),
        }
    }
}

pub struct BatchLock {
    inner: std::sync::Mutex<bool>, // true = blocking new locks
    condvar: std::sync::Condvar,
    active_count: std::sync::atomic::AtomicUsize,
}

pub struct LockGuard {
    lock: Arc<BatchLock>,
}

impl BatchLock {
    pub fn new() -> Arc<Self> {
        Arc::new(BatchLock {
            inner: std::sync::Mutex::new(false),
            condvar: std::sync::Condvar::new(),
            active_count: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    // Acquire a lock (blocks if waiting for all to unlock)
    pub fn lock(self: &Arc<Self>) -> LockGuard {
        let mut blocking = self.inner.lock().unwrap();

        // Wait while new locks are blocked
        while *blocking {
            blocking = self.condvar.wait(blocking).unwrap();
        }

        self.active_count.fetch_add(1, Ordering::SeqCst);

        LockGuard {
            lock: Arc::clone(self),
        }
    }

    // Block new locks and wait for all current locks to finish
    pub fn wait_all_unlock(self: &Arc<Self>) {
        // Block new locks
        *self.inner.lock().unwrap() = true;

        // Wait for all active locks to finish
        while self.active_count.load(Ordering::SeqCst) > 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // Allow new locks again
        *self.inner.lock().unwrap() = false;
        self.condvar.notify_all();
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Automatically release lock when guard is dropped
        self.lock.active_count.fetch_sub(1, Ordering::SeqCst);
    }
}
