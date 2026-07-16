use crate::{PlatformError, PlatformResult, PrivateAppPaths};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

#[derive(Debug, Default)]
struct CoordinatorState {
    readers: usize,
    writer_active: bool,
    writers_waiting: usize,
}

#[derive(Debug, Default)]
struct CoordinatorInner {
    state: Mutex<CoordinatorState>,
    changed: Condvar,
}

static GLOBAL_COORDINATOR: OnceLock<Arc<CoordinatorInner>> = OnceLock::new();
static OPEN_STORES: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

/// Process-global publication barrier shared by maintenance and command entry points.
#[derive(Clone, Debug)]
pub struct MaintenanceCoordinator {
    inner: Arc<CoordinatorInner>,
}

impl Default for MaintenanceCoordinator {
    fn default() -> Self {
        Self::global()
    }
}

impl MaintenanceCoordinator {
    pub fn global() -> Self {
        Self {
            inner: Arc::clone(
                GLOBAL_COORDINATOR.get_or_init(|| Arc::new(CoordinatorInner::default())),
            ),
        }
    }

    pub fn acquire_shared(&self) -> PlatformResult<SharedMaintenancePermit> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| PlatformError::Conflict("maintenance_coordinator_poisoned"))?;
        while state.writer_active || state.writers_waiting != 0 {
            state = self
                .inner
                .changed
                .wait(state)
                .map_err(|_| PlatformError::Conflict("maintenance_coordinator_poisoned"))?;
        }
        state.readers = state
            .readers
            .checked_add(1)
            .ok_or(PlatformError::Corrupt("maintenance_reader_count"))?;
        drop(state);
        Ok(SharedMaintenancePermit {
            inner: Arc::clone(&self.inner),
        })
    }

    pub fn acquire_exclusive(&self) -> PlatformResult<ExclusiveMaintenancePermit> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| PlatformError::Conflict("maintenance_coordinator_poisoned"))?;
        state.writers_waiting = state
            .writers_waiting
            .checked_add(1)
            .ok_or(PlatformError::Corrupt("maintenance_writer_count"))?;
        while state.writer_active || state.readers != 0 {
            state = self
                .inner
                .changed
                .wait(state)
                .map_err(|_| PlatformError::Conflict("maintenance_coordinator_poisoned"))?;
        }
        state.writers_waiting -= 1;
        state.writer_active = true;
        drop(state);
        Ok(ExclusiveMaintenancePermit {
            inner: Arc::clone(&self.inner),
        })
    }
}

#[derive(Debug)]
pub struct SharedMaintenancePermit {
    inner: Arc<CoordinatorInner>,
}

impl Drop for SharedMaintenancePermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            debug_assert!(state.readers > 0);
            state.readers = state.readers.saturating_sub(1);
            if state.readers == 0 {
                self.inner.changed.notify_all();
            }
        }
    }
}

#[derive(Debug)]
pub struct ExclusiveMaintenancePermit {
    inner: Arc<CoordinatorInner>,
}

impl Drop for ExclusiveMaintenancePermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            debug_assert!(state.writer_active);
            state.writer_active = false;
            self.inner.changed.notify_all();
        }
    }
}

/// Lifetime-held, process-level authority for opening one private store.
#[derive(Debug)]
pub struct StoreLock {
    file: File,
    canonical_path: PathBuf,
}

impl StoreLock {
    pub fn acquire(paths: &PrivateAppPaths) -> PlatformResult<Self> {
        let canonical_path = paths.root.join(".wardrobe.lock");
        {
            let mut stores = OPEN_STORES
                .get_or_init(|| Mutex::new(HashSet::new()))
                .lock()
                .map_err(|_| PlatformError::Conflict("store_lock_registry_poisoned"))?;
            if !stores.insert(canonical_path.clone()) {
                return Err(PlatformError::Conflict("store_already_open"));
            }
        }
        let result = Self::acquire_registered(paths, canonical_path.clone());
        if result.is_err() {
            if let Ok(mut stores) = OPEN_STORES
                .get_or_init(|| Mutex::new(HashSet::new()))
                .lock()
            {
                stores.remove(&canonical_path);
            }
        }
        result
    }

    fn acquire_registered(
        paths: &PrivateAppPaths,
        canonical_path: PathBuf,
    ) -> PlatformResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&paths.store_lock)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(PlatformError::Corrupt("store_lock_identity"));
        }
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock
                || error.raw_os_error() == Some(libc::EWOULDBLOCK)
                || error.raw_os_error() == Some(libc::EAGAIN)
            {
                return Err(PlatformError::Conflict("store_already_open"));
            }
            return Err(error.into());
        }
        Ok(Self {
            file,
            canonical_path,
        })
    }

    pub(crate) fn protects(&self, paths: &PrivateAppPaths) -> bool {
        self.canonical_path == paths.store_lock
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
        if let Ok(mut stores) = OPEN_STORES
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
        {
            stores.remove(&self.canonical_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn assert_send<T: Send>() {}

    #[test]
    fn permits_and_store_lock_are_send() {
        assert_send::<SharedMaintenancePermit>();
        assert_send::<ExclusiveMaintenancePermit>();
        assert_send::<StoreLock>();
    }

    #[test]
    fn exclusive_waits_for_shared_and_blocks_new_shared() {
        let coordinator = MaintenanceCoordinator {
            inner: Arc::new(CoordinatorInner::default()),
        };
        let shared = coordinator.acquire_shared().unwrap();
        let (writer_acquired_tx, writer_acquired_rx) = mpsc::channel();
        let writer_coordinator = coordinator.clone();
        let writer = thread::spawn(move || {
            let permit = writer_coordinator.acquire_exclusive().unwrap();
            writer_acquired_tx.send(()).unwrap();
            permit
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if coordinator.inner.state.lock().unwrap().writers_waiting == 1 {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        }

        let (reader_tx, reader_rx) = mpsc::channel();
        let reader_coordinator = coordinator.clone();
        let reader = thread::spawn(move || {
            let permit = reader_coordinator.acquire_shared().unwrap();
            reader_tx.send(()).unwrap();
            permit
        });
        assert!(reader_rx.recv_timeout(Duration::from_millis(50)).is_err());

        drop(shared);
        writer_acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert!(reader_rx.recv_timeout(Duration::from_millis(50)).is_err());
        let exclusive = writer.join().unwrap();
        drop(exclusive);
        reader_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(reader.join().unwrap());
    }

    #[test]
    fn store_lock_releases_for_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let lock = StoreLock::acquire(&paths).unwrap();
        assert_eq!(lock.file.metadata().unwrap().mode() & 0o777, 0o600);
        assert!(matches!(
            StoreLock::acquire(&paths),
            Err(PlatformError::Conflict("store_already_open"))
        ));
        drop(lock);
        StoreLock::acquire(&paths).unwrap();
    }
}
