//! Durable block state (ADR-4, R26-04, R27-03/04).
//!
//! One writer thread owns the file: callers hand it snapshots numbered by generation and never
//! wait for the disk, so a slow or hung filesystem cannot stall the maintenance tick (expiry,
//! reconciliation, heartbeat). The writer always writes the newest snapshot it has (a burst of
//! changes costs one write) and never an older one after a newer one; a failed write is retried
//! until a newer snapshot replaces it.
//!
//! Contract: an operator decision waits for its generation to be durable, up to
//! [`DURABLE_WAIT`]; past that the answer says the outcome is not yet known. A detector decision
//! is durable within one tick plus the write time. Health turns bad when a change has waited
//! longer than [`STALE_AFTER`] (hung or failing disk), and stays bad after a failed restore until
//! the operator accepts the loss.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use crate::block_table::Persisted;

/// How long an operator decision waits for its write before answering.
pub const DURABLE_WAIT: Duration = Duration::from_secs(2);
/// A change not durable after this long makes the node DEGRADED.
pub const STALE_AFTER: Duration = Duration::from_secs(5);
/// Pause before retrying a failed write when nothing newer arrives.
const RETRY_AFTER: Duration = Duration::from_secs(1);

pub type WriteFn = dyn Fn(&Path, &Persisted) -> std::io::Result<()> + Send + Sync;

/// What startup found in the state file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Restore {
    /// No state file: a first start.
    Fresh,
    Restored {
        restored: usize,
        refused: usize,
    },
    /// The file could not be read or parsed; its bytes are kept at `kept` if they could be.
    Failed {
        why: String,
        kept: Option<PathBuf>,
    },
    /// The operator accepted starting without the lost state (`ACCEPT_STATE_LOSS`).
    LossAccepted,
}

impl Restore {
    pub fn ok(&self) -> bool {
        !matches!(self, Restore::Failed { .. })
    }
}

struct Shared {
    /// Last generation handed to the writer, and the last one on disk.
    submitted: AtomicU64,
    durable: AtomicU64,
    /// When the oldest change not yet on disk was handed over (ms since epoch; 0: none).
    pending_since_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
    restore: Mutex<Restore>,
    durable_tx: tokio::sync::watch::Sender<u64>,
}

pub struct StateStore {
    path: PathBuf,
    shared: Arc<Shared>,
    tx: Mutex<mpsc::Sender<(u64, Persisted)>>,
}

impl StateStore {
    pub fn new(path: PathBuf) -> Self {
        Self::with_writer(path, Arc::new(save_state))
    }

    pub fn with_writer(path: PathBuf, write: Arc<WriteFn>) -> Self {
        let (tx, rx) = mpsc::channel::<(u64, Persisted)>();
        let (durable_tx, _) = tokio::sync::watch::channel(0);
        let shared = Arc::new(Shared {
            submitted: AtomicU64::new(0),
            durable: AtomicU64::new(0),
            pending_since_ms: AtomicU64::new(0),
            last_error: Mutex::new(None),
            restore: Mutex::new(Restore::Fresh),
            durable_tx,
        });
        let (writer_shared, writer_path) = (shared.clone(), path.clone());
        std::thread::Builder::new()
            .name("sokol-state-writer".into())
            .spawn(move || writer_loop(&writer_path, &rx, &writer_shared, &*write))
            .map_err(|e| log::error!("[State] Cannot start the state writer: {}", e))
            .ok();
        Self {
            path,
            shared,
            tx: Mutex::new(tx),
        }
    }

    /// Hands a snapshot to the writer and returns its generation. Never waits for the disk.
    pub fn submit(&self, state: Persisted, now_ms: u64) -> u64 {
        let generation = self.shared.submitted.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.shared.pending_since_ms.compare_exchange(
            0,
            now_ms.max(1),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        let sent = self
            .tx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .send((generation, state));
        if sent.is_err() {
            self.set_error("the state writer is gone".into());
        }
        generation
    }

    /// Waits until `generation` (or a newer one) is on disk, at most `wait`.
    pub async fn wait_durable(&self, generation: u64, wait: Duration) -> Result<(), String> {
        let mut rx = self.shared.durable_tx.subscribe();
        let reached = tokio::time::timeout(wait, rx.wait_for(|d| *d >= generation)).await;
        match reached {
            Ok(Ok(_)) => Ok(()),
            _ => Err(match self.last_error() {
                Some(e) => format!("not yet durable: {}", e),
                None => format!(
                    "not yet durable after {} ms (write pending)",
                    wait.as_millis()
                ),
            }),
        }
    }

    /// The generation last handed to the writer (0: none yet).
    pub fn submitted(&self) -> u64 {
        self.shared.submitted.load(Ordering::SeqCst)
    }

    pub fn durable(&self) -> u64 {
        self.shared.durable.load(Ordering::SeqCst)
    }

    /// How long the oldest change not yet on disk has waited.
    pub fn pending_for(&self, now_ms: u64) -> Duration {
        match self.shared.pending_since_ms.load(Ordering::SeqCst) {
            0 => Duration::ZERO,
            since => Duration::from_millis(now_ms.saturating_sub(since)),
        }
    }

    pub fn last_error(&self) -> Option<String> {
        self.shared
            .last_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn set_error(&self, e: String) {
        *self
            .shared
            .last_error
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(e);
    }

    pub fn restore_status(&self) -> Restore {
        self.shared
            .restore
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn set_restore(&self, status: Restore) {
        *self
            .shared
            .restore
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = status;
    }

    /// `ACCEPT_STATE_LOSS`: the operator chose to run without the state that failed to restore.
    pub fn accept_loss(&self) -> bool {
        let mut restore = self
            .shared
            .restore
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let failed = !restore.ok();
        if failed {
            *restore = Restore::LossAccepted;
        }
        failed
    }

    /// Healthy: the restore did not fail (or its loss was accepted), no write error stands and
    /// no change has waited longer than [`STALE_AFTER`].
    pub fn healthy(&self, now_ms: u64) -> bool {
        self.restore_status().ok()
            && self.last_error().is_none()
            && self.pending_for(now_ms) <= STALE_AFTER
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the state file. A file that cannot be parsed is kept aside (never overwritten) so the
    /// next write does not destroy the evidence; the caller records the outcome with
    /// [`StateStore::set_restore`].
    pub fn read(&self) -> Result<Option<Persisted>, Restore> {
        read_state(&self.path)
    }
}

fn now() -> u64 {
    crate::p2p::now_ms()
}

fn writer_loop(
    path: &Path,
    rx: &mpsc::Receiver<(u64, Persisted)>,
    shared: &Shared,
    write: &WriteFn,
) {
    let mut pending: Option<(u64, Persisted)> = None;
    let mut written = 0u64;
    loop {
        // Wait for work; while a failed write is pending, wait at most RETRY_AFTER.
        let next = match &pending {
            None => rx.recv().ok(),
            Some(_) => match rx.recv_timeout(RETRY_AFTER) {
                Ok(item) => Some(item),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            },
        };
        if pending.is_none() && next.is_none() {
            return; // every sender is gone
        }
        // Coalesce: only the newest snapshot matters.
        for item in next.into_iter().chain(rx.try_iter()) {
            if pending.as_ref().is_none_or(|(g, _)| item.0 > *g) {
                pending = Some(item);
            }
        }
        let Some((generation, state)) = pending.take() else {
            continue;
        };
        if generation <= written {
            continue;
        }
        match write(path, &state) {
            Ok(()) => {
                written = generation;
                shared.durable.store(generation, Ordering::SeqCst);
                // Anything submitted after this snapshot is still pending, from now on.
                let newer = shared.submitted.load(Ordering::SeqCst) > generation;
                shared
                    .pending_since_ms
                    .store(if newer { now() } else { 0 }, Ordering::SeqCst);
                let was = shared
                    .last_error
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take();
                if was.is_some() {
                    log::warn!("[State] {} writable again", path.display());
                }
                shared.durable_tx.send_replace(generation);
            }
            Err(e) => {
                let mut last = shared.last_error.lock().unwrap_or_else(|p| p.into_inner());
                if last.is_none() {
                    log::error!(
                        "[State] Cannot write {}: {}; node is DEGRADED, retrying",
                        path.display(),
                        e
                    );
                }
                *last = Some(e.to_string());
                pending = Some((generation, state));
            }
        }
    }
}

pub fn save_state(path: &Path, state: &Persisted) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&serde_json::to_vec(state).map_err(std::io::Error::other)?)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    // The rename is durable only once the directory entry is (R26-04).
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// `Ok(None)`: no state file (a first start).
pub fn read_state(path: &Path) -> Result<Option<Persisted>, Restore> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Restore::Failed {
                why: format!("cannot read {}: {}", path.display(), e),
                kept: None,
            })
        }
    };
    serde_json::from_slice::<Persisted>(&bytes)
        .map(Some)
        .map_err(|e| Restore::Failed {
            why: format!("{} is not a valid state file: {}", path.display(), e),
            kept: keep_aside(path),
        })
}

/// Links the unreadable file to the first free `<path>.corrupt[.N]` (never replacing one).
fn keep_aside(path: &Path) -> Option<PathBuf> {
    (0..1000)
        .map(|n| {
            let mut name = path.as_os_str().to_owned();
            name.push(".corrupt");
            if n > 0 {
                name.push(format!(".{}", n));
            }
            PathBuf::from(name)
        })
        .find_map(|candidate| match std::fs::hard_link(path, &candidate) {
            Ok(()) => Some(Some(candidate)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
            Err(_) => Some(None),
        })
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(n: usize) -> Persisted {
        Persisted {
            operator_lifts: (0..n).map(|i| (format!("{:064x}", i), None)).collect(),
            ..Persisted::default()
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sokol-state-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("state.json")
    }

    /// A disk that blocks until released, recording the generations (by size) it wrote.
    #[allow(clippy::type_complexity)]
    fn gated() -> (
        Arc<WriteFn>,
        Arc<(Mutex<bool>, std::sync::Condvar)>,
        Arc<Mutex<Vec<usize>>>,
    ) {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let written = Arc::new(Mutex::new(Vec::new()));
        let (g, w) = (gate.clone(), written.clone());
        let write: Arc<WriteFn> = Arc::new(move |_: &Path, s: &Persisted| {
            let (lock, cv) = &*g;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
            w.lock().unwrap().push(s.operator_lifts.len());
            Ok(())
        });
        (write, gate, written)
    }

    fn release(gate: &(Mutex<bool>, std::sync::Condvar)) {
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
    }

    #[tokio::test]
    async fn a_hung_disk_neither_blocks_callers_nor_looks_healthy() {
        // R27-03: submitting returns at once while the write hangs; the wait for durability
        // times out; health turns bad after STALE_AFTER; once the disk answers, the newest
        // snapshot is written, in order, and health comes back.
        let (write, gate, written) = gated();
        let store = StateStore::with_writer(temp("hung"), write);
        let t0 = now();
        let started = std::time::Instant::now();
        let first = store.submit(state(1), t0);
        tokio::time::sleep(Duration::from_millis(50)).await; // the writer takes it and hangs
        let _ = store.submit(state(2), t0);
        let last = store.submit(state(3), t0);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "submit waited for the disk"
        );
        assert!(store
            .wait_durable(first, Duration::from_millis(100))
            .await
            .is_err());
        assert!(
            store.healthy(t0 + 1000),
            "a short wait is not yet a problem"
        );
        let late = t0 + STALE_AFTER.as_millis() as u64 + 1000;
        assert!(!store.healthy(late), "a hung write must turn health bad");

        release(&gate);
        store
            .wait_durable(last, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            *written.lock().unwrap(),
            vec![1, 3],
            "coalesced, newest last"
        );
        assert_eq!(store.durable(), last);
        assert!(store.healthy(now()));
    }

    #[tokio::test]
    async fn a_failing_disk_is_retried_and_reported() {
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let f = fail.clone();
        let write: Arc<WriteFn> = Arc::new(move |p: &Path, s: &Persisted| {
            if f.load(Ordering::SeqCst) {
                Err(std::io::Error::other("disk full"))
            } else {
                save_state(p, s)
            }
        });
        let path = temp("failing");
        let store = StateStore::with_writer(path.clone(), write);
        let generation = store.submit(state(2), now());
        let err = store
            .wait_durable(generation, Duration::from_millis(300))
            .await
            .unwrap_err();
        assert!(err.contains("disk full"), "{}", err);
        assert!(!store.healthy(now()));
        fail.store(false, Ordering::SeqCst);
        store
            .wait_durable(generation, Duration::from_secs(3))
            .await
            .unwrap();
        assert!(store.healthy(now()));
        assert_eq!(read_state(&path).unwrap().unwrap(), state(2));
    }

    #[test]
    fn restore_tells_fresh_corrupt_and_unreadable_apart() {
        let path = temp("restore");
        assert_eq!(read_state(&path), Ok(None), "no file: a first start");
        save_state(&path, &state(1)).unwrap();
        assert_eq!(read_state(&path), Ok(Some(state(1))));

        std::fs::write(&path, b"{ not json").unwrap();
        std::fs::write(path.with_extension("json.corrupt"), b"an earlier one").unwrap();
        match read_state(&path) {
            Err(Restore::Failed {
                kept: Some(kept), ..
            }) => {
                assert_eq!(
                    std::fs::read(&kept).unwrap(),
                    b"{ not json",
                    "the bytes are kept"
                );
                assert_eq!(
                    std::fs::read(path.with_extension("json.corrupt")).unwrap(),
                    b"an earlier one",
                    "an earlier copy is not overwritten"
                );
            }
            other => panic!("expected a failed restore, got {:?}", other),
        }

        let dir = path.with_extension("dir");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            matches!(read_state(&dir), Err(Restore::Failed { kept: None, .. })),
            "an unreadable path is a failure, not a first start"
        );
    }

    #[test]
    fn a_failed_restore_keeps_the_node_degraded_until_the_loss_is_accepted() {
        let store = StateStore::with_writer(temp("sticky"), Arc::new(save_state));
        assert!(store.healthy(now()));
        store.set_restore(Restore::Failed {
            why: "corrupt".into(),
            kept: None,
        });
        assert!(
            !store.healthy(now()),
            "R27-04: a failed restore looked healthy"
        );
        assert!(store.accept_loss());
        assert!(store.healthy(now()));
        assert!(!store.accept_loss(), "nothing left to accept");
    }
}
