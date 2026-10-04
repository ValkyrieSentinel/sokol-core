//! Durable block state (ADR-4, R26-04, R27-03/04).
//!
//! One writer thread owns the file: callers hand it snapshots numbered by generation and never
//! wait for the disk, so a slow or hung filesystem cannot stall the maintenance tick (expiry,
//! reconciliation, heartbeat). One replaceable handoff retains the newest submission while the
//! writer owns one in-flight/retry snapshot; a burst cannot accumulate retained snapshots behind
//! a hung write. The writer never writes an older generation after a newer one; a failed write
//! is retried until a newer snapshot replaces it.
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

struct Snapshot {
    generation: u64,
    state: Persisted,
    /// First handoff still queued, retained when newer snapshots replace it.
    since_ms: u64,
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
    /// One replaceable snapshot, separate from the writer's in-flight/retry state.
    /// This lock also orders generation assignment and completion accounting.
    latest: Mutex<Option<Snapshot>>,
}

pub struct StateStore {
    path: PathBuf,
    shared: Arc<Shared>,
    tx: mpsc::SyncSender<()>,
}

impl StateStore {
    pub fn new(path: PathBuf) -> Self {
        Self::with_writer(path, Arc::new(save_state))
    }

    pub fn with_writer(path: PathBuf, write: Arc<WriteFn>) -> Self {
        // Notifications carry no state; one outstanding wake is enough. Snapshots
        // coalesce at submission, even while the writer is stuck in the filesystem.
        let (tx, rx) = mpsc::sync_channel::<()>(1);
        let (durable_tx, _) = tokio::sync::watch::channel(0);
        let shared = Arc::new(Shared {
            submitted: AtomicU64::new(0),
            durable: AtomicU64::new(0),
            pending_since_ms: AtomicU64::new(0),
            last_error: Mutex::new(None),
            restore: Mutex::new(Restore::Fresh),
            durable_tx,
            latest: Mutex::new(None),
        });
        let (writer_shared, writer_path) = (shared.clone(), path.clone());
        std::thread::Builder::new()
            .name("sokol-state-writer".into())
            .spawn(move || writer_loop(&writer_path, &rx, &writer_shared, &*write))
            .map_err(|e| log::error!("[State] Cannot start the state writer: {}", e))
            .ok();
        Self { path, shared, tx }
    }

    /// Hands a snapshot to the writer and returns its generation. Never waits for the disk.
    pub fn submit(&self, state: Persisted, now_ms: u64) -> u64 {
        let generation = {
            let mut latest = self.shared.latest.lock().unwrap_or_else(|p| p.into_inner());
            let generation = self.shared.submitted.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = self.shared.pending_since_ms.compare_exchange(
                0,
                now_ms.max(1),
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            let since_ms = latest.as_ref().map_or(now_ms.max(1), |s| s.since_ms);
            *latest = Some(Snapshot {
                generation,
                state,
                since_ms,
            });
            generation
        };
        // A full notification channel already wakes the writer. Do not wait for
        // it, and do not discard the latest snapshot just because the wake coalesced.
        if let Err(mpsc::TrySendError::Disconnected(_)) = self.tx.try_send(()) {
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

fn writer_loop(path: &Path, rx: &mpsc::Receiver<()>, shared: &Shared, write: &WriteFn) {
    let mut pending: Option<(u64, Persisted)> = None;
    let mut written = 0u64;
    loop {
        // Wait for work; while a failed write is pending, wait at most RETRY_AFTER.
        let wake = match &pending {
            None => rx.recv().ok(),
            Some(_) => match rx.recv_timeout(RETRY_AFTER) {
                Ok(item) => Some(item),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            },
        };
        if pending.is_none() && wake.is_none() {
            return; // every sender is gone
        }
        // Take one newest handoff. No backlog drain can grow or starve writes.
        {
            let mut latest = shared.latest.lock().unwrap_or_else(|p| p.into_inner());
            if latest
                .as_ref()
                .is_some_and(|item| pending.as_ref().is_none_or(|(g, _)| item.generation > *g))
            {
                // Drop the failed predecessor before taking its replacement, while
                // producers cannot refill the slot: retain at most two snapshots.
                drop(pending.take());
                pending = latest.take().map(|s| (s.generation, s.state));
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
                // Serialize this reset with submit: a concurrently handed newer
                // snapshot must not lose its pending-age marker after this write.
                let latest = shared.latest.lock().unwrap_or_else(|p| p.into_inner());
                shared.durable.store(generation, Ordering::SeqCst);
                // The queued work keeps its first submission time across coalescing.
                // Completing an older write must not renew its health grace period.
                let since_ms = latest.as_ref().map_or(0, |s| s.since_ms);
                shared.pending_since_ms.store(since_ms, Ordering::SeqCst);
                drop(latest);
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
    // The layout is checked first, so a file of another schema is named as such, not as corrupt.
    #[derive(serde::Deserialize)]
    struct Head {
        schema: Option<u32>,
    }
    if let Ok(Head {
        schema: Some(schema),
    }) = serde_json::from_slice::<Head>(&bytes)
    {
        if schema != crate::block_table::STATE_SCHEMA {
            return Err(Restore::Failed {
                why: format!(
                    "{} has state schema {}, this build reads {} (no migration)",
                    path.display(),
                    schema,
                    crate::block_table::STATE_SCHEMA
                ),
                kept: keep_aside(path),
            });
        }
    }
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
    async fn finishing_an_older_write_does_not_refresh_pending_health() {
        let gates = Arc::new([
            (Mutex::new(false), std::sync::Condvar::new()),
            (Mutex::new(false), std::sync::Condvar::new()),
        ]);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (g, c) = (gates.clone(), calls.clone());
        let write: Arc<WriteFn> = Arc::new(move |path, snapshot| {
            let call = c.fetch_add(1, Ordering::SeqCst);
            entered_tx.send(call).unwrap();
            if let Some(gate) = g.get(call) {
                let mut open = gate.0.lock().unwrap();
                while !*open {
                    open = gate.1.wait(open).unwrap();
                }
            }
            save_state(path, snapshot)
        });
        let store = StateStore::with_writer(temp("pending-age"), write);
        // Synthetic old handoff times avoid sleeping through the health threshold.
        let t0 = now().saturating_sub(20_000);
        let first = store.submit(state(1), t0);
        assert_eq!(entered_rx.recv_timeout(Duration::from_secs(2)).unwrap(), 0);
        store.submit(state(2), t0 + 1000);
        let last = store.submit(state(3), t0 + 2000);
        release(&gates[0]);
        assert_eq!(entered_rx.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
        let during_durable = store.durable();
        let age = store.pending_for(now());
        let healthy = store.healthy(now());
        let unknown = store
            .wait_durable(last, Duration::from_millis(30))
            .await
            .is_err();
        release(&gates[1]);
        store
            .wait_durable(last, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            during_durable, first,
            "queued snapshot was advertised durable before its write"
        );
        assert!(
            age >= Duration::from_secs(19),
            "older completion reset the queued snapshot's age: {age:?}"
        );
        assert!(
            !healthy && unknown,
            "unfinished old work acquired a fresh health grace period"
        );
        assert_eq!(read_state(store.path()).unwrap().unwrap(), state(3));
        assert!(store.healthy(now()));
    }

    #[tokio::test]
    async fn a_hung_writer_retains_only_the_latest_handoff_and_recovers_it() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let written = Arc::new(Mutex::new(Vec::new()));
        let (g, w) = (gate.clone(), written.clone());
        let write: Arc<WriteFn> = Arc::new(move |path, snapshot| {
            entered_tx.send(()).unwrap();
            let mut open = g.0.lock().unwrap();
            while !*open {
                open = g.1.wait(open).unwrap();
            }
            w.lock().unwrap().push(snapshot.operator_lifts.len());
            save_state(path, snapshot)
        });
        let store = StateStore::with_writer(temp("bounded-handoff"), write);
        let t0 = now();
        let first = store.submit(state(1), t0);
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = std::time::Instant::now();
        let mut last = first;
        for n in 2..=400 {
            last = store.submit(state(n), t0 + n as u64);
        }
        let elapsed = started.elapsed();
        {
            let slot = store.shared.latest.lock().unwrap();
            let latest = slot.as_ref().unwrap();
            assert_eq!(latest.generation, last);
            assert_eq!(latest.state, state(400));
            assert_eq!(latest.since_ms, t0 + 2, "replacement renewed pending age");
        }
        let unknown = store
            .wait_durable(last, Duration::from_millis(30))
            .await
            .is_err();
        let before_durable = store.durable();
        release(&gate);
        store
            .wait_durable(last, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(
            elapsed < Duration::from_secs(2),
            "handoff waited for the filesystem"
        );
        assert!(unknown && before_durable == 0);
        assert_eq!(*written.lock().unwrap(), vec![1, 400]);
        assert_eq!(read_state(store.path()).unwrap().unwrap(), state(400));
        assert!(store.healthy(now()));
    }

    #[tokio::test]
    async fn concurrent_submitters_preserve_the_latest_generation_and_snapshot_pair() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let written = Arc::new(Mutex::new(Vec::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (g, w) = (gate.clone(), written.clone());
        let write: Arc<WriteFn> = Arc::new(move |_, snapshot| {
            entered_tx.send(()).unwrap();
            let mut open = g.0.lock().unwrap();
            while !*open {
                open = g.1.wait(open).unwrap();
            }
            w.lock().unwrap().push(snapshot.operator_lifts.len());
            Ok(())
        });
        let store = Arc::new(StateStore::with_writer(temp("concurrent-handoff"), write));
        store.submit(state(1), now());
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut senders = Vec::new();
        for n in 2..=9 {
            let (s, b) = (store.clone(), barrier.clone());
            senders.push(std::thread::spawn(move || {
                b.wait();
                (s.submit(state(n), now()), n)
            }));
        }
        barrier.wait();
        let expected = senders
            .into_iter()
            .map(|t| t.join().unwrap())
            .max_by_key(|(g, _)| *g)
            .unwrap();
        let recorded = {
            let slot = store.shared.latest.lock().unwrap();
            slot.as_ref()
                .map(|s| (s.generation, s.state.operator_lifts.len()))
        };
        release(&gate);
        store
            .wait_durable(expected.0, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(recorded, Some(expected));
        assert_eq!(store.submitted(), expected.0);
        assert_eq!(store.durable(), expected.0);
        assert_eq!(written.lock().unwrap().last(), Some(&expected.1));
    }

    #[tokio::test]
    async fn a_failed_write_is_replaced_by_the_newest_queued_snapshot() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (g, a) = (gate.clone(), attempts.clone());
        let write: Arc<WriteFn> = Arc::new(move |path, snapshot| {
            let n = snapshot.operator_lifts.len();
            a.lock().unwrap().push(n);
            if n == 1 {
                entered_tx.send(()).unwrap();
                let mut open = g.0.lock().unwrap();
                while !*open {
                    open = g.1.wait(open).unwrap();
                }
                return Err(std::io::Error::other("first write refused"));
            }
            save_state(path, snapshot)
        });
        let store = StateStore::with_writer(temp("replace-failure"), write);
        let first = store.submit(state(1), now());
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        store.submit(state(2), now());
        let last = store.submit(state(3), now());
        let unknown = store
            .wait_durable(first, Duration::from_millis(30))
            .await
            .is_err();
        release(&gate);
        store
            .wait_durable(last, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(unknown);
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![1, 3],
            "failed predecessor or superseded snapshot was written again"
        );
        assert_eq!(store.durable(), last);
        assert_eq!(read_state(store.path()).unwrap().unwrap(), state(3));
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
    fn another_schema_is_refused_by_name_and_an_unversioned_file_is_schema_1() {
        let path = temp("schema");
        save_state(&path, &state(2)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("\"schema\":1"),
            "the schema is written: {}",
            text
        );

        std::fs::write(&path, text.replace("\"schema\":1", "\"schema\":2")).unwrap();
        match read_state(&path) {
            Err(Restore::Failed { why, kept: Some(_) }) => {
                assert!(
                    why.contains("state schema 2, this build reads 1"),
                    "{}",
                    why
                )
            }
            other => panic!("expected a refused schema, got {:?}", other),
        }

        std::fs::write(&path, text.replace("\"schema\":1,", "")).unwrap();
        assert_eq!(
            read_state(&path).unwrap().unwrap(),
            state(2),
            "a file from before the field reads as schema 1"
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
