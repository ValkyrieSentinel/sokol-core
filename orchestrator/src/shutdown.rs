//! Own the async producers that may change the table or submit audit records.
//! Cancellation is at an await boundary: mutations and their audit submission must share
//! a poll, before network/telemetry awaits. Unanswered requests may have taken effect.
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::task::{JoinHandle, JoinSet};

type Tasks = Mutex<Option<JoinSet<()>>>;

pub struct Producers {
    tasks: Arc<Tasks>,
}

#[derive(Clone)]
pub struct Spawner {
    // Children must not keep their own owner alive through a reference cycle.
    tasks: Weak<Tasks>,
}

impl Default for Producers {
    fn default() -> Self {
        Self::new()
    }
}

impl Producers {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(Mutex::new(Some(JoinSet::new()))),
        }
    }

    pub fn spawner(&self) -> Spawner {
        Spawner {
            tasks: Arc::downgrade(&self.tasks),
        }
    }

    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> bool {
        self.spawner().spawn(task)
    }

    /// Close child registration, cancel every admitted producer, then await their drop.
    /// A deadline that merely drops a JoinHandle would detach a still-running producer.
    pub async fn quiesce(&mut self) {
        let tasks = self.tasks.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(mut tasks) = tasks {
            tasks.abort_all();
            while let Some(result) = tasks.join_next().await {
                report(result);
            }
        }
    }
}

impl Spawner {
    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> bool {
        let Some(owner) = self.tasks.upgrade() else {
            return false;
        };
        let mut tasks = owner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(tasks) = tasks.as_mut() else {
            return false;
        };
        // Short-lived socket handlers must not accumulate completed entries forever.
        while let Some(result) = tasks.try_join_next() {
            report(result);
        }
        tasks.spawn(task);
        true
    }
}

fn report(result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        if !error.is_cancelled() {
            log::error!("[Shutdown] Producer failed: {}", error);
        }
    }
}

/// Give an independent cleanup worker its budget, then cancel AND join on timeout.
/// False means completion was not successful; it never means the task is still running.
pub async fn finish_within(mut task: JoinHandle<()>, wait: Duration) -> bool {
    match tokio::time::timeout(wait, &mut task).await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            report(Err(error));
            false
        }
        Err(_) => {
            task.abort();
            report(task.await);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::oneshot;

    struct OnDrop(Arc<AtomicBool>);
    impl Drop for OnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn quiesce_joins_a_stalled_producer_before_final_state_and_audit() {
        let mut tasks = Producers::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let decision = Arc::new(AtomicUsize::new(0));
        let (started, ready) = oneshot::channel();
        let (release, blocked) = oneshot::channel::<()>();
        let (d, state) = (dropped.clone(), decision.clone());
        tasks.spawn(async move {
            let _drop = OnDrop(d);
            state.store(1, Ordering::SeqCst); // accepted decision and audit submission
            let _ = started.send(());
            let _ = blocked.await; // stuck telemetry/ACK
            state.store(2, Ordering::SeqCst); // would invalidate a final snapshot
        });
        ready.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), tasks.quiesce())
            .await
            .unwrap();
        let final_state = decision.load(Ordering::SeqCst);
        assert!(
            dropped.load(Ordering::SeqCst),
            "producer must be dropped before finalization"
        );
        let _ = release.send(());
        tokio::task::yield_now().await;
        assert_eq!(final_state, 1);
        assert_eq!(
            decision.load(Ordering::SeqCst),
            final_state,
            "late decision after barrier"
        );
    }

    #[tokio::test]
    async fn child_handlers_are_joined_with_their_listener() {
        let mut tasks = Producers::new();
        let children = tasks.spawner();
        let dropped = Arc::new(AtomicBool::new(false));
        let d = dropped.clone();
        let (started, ready) = oneshot::channel();
        tasks.spawn(async move {
            children.spawn(async move {
                let _drop = OnDrop(d);
                let _ = started.send(());
                std::future::pending::<()>().await;
            });
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        tasks.quiesce().await;
        assert!(
            dropped.load(Ordering::SeqCst),
            "accepted child outlived its listener"
        );
    }

    #[tokio::test]
    async fn a_closed_owner_refuses_late_child_registration() {
        let mut tasks = Producers::new();
        let children = tasks.spawner();
        tasks.quiesce().await;
        let executed = Arc::new(AtomicBool::new(false));
        let ran = executed.clone();
        assert!(!children.spawn(async move {
            ran.store(true, Ordering::SeqCst);
        }));
        tokio::task::yield_now().await;
        assert!(!executed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn dropping_the_owner_does_not_leave_a_child_reference_cycle() {
        let tasks = Producers::new();
        let children = tasks.spawner();
        let dropped = Arc::new(AtomicBool::new(false));
        let d = dropped.clone();
        let (started, ready) = oneshot::channel();
        tasks.spawn(async move {
            let _children = children;
            let _drop = OnDrop(d);
            let _ = started.send(());
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        drop(tasks);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owner drop must cancel children on startup error");
    }

    #[tokio::test]
    async fn a_timed_out_cleanup_worker_is_cancelled_and_joined() {
        let dropped = Arc::new(AtomicBool::new(false));
        let d = dropped.clone();
        let (started, ready) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let _drop = OnDrop(d);
            let _ = started.send(());
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        assert!(!finish_within(worker, Duration::from_millis(1)).await);
        assert!(
            dropped.load(Ordering::SeqCst),
            "timeout detached the cleanup worker"
        );
        assert!(finish_within(tokio::spawn(async {}), Duration::from_secs(1)).await);
        assert!(
            !finish_within(
                tokio::spawn(async { panic!("worker failure") }),
                Duration::from_secs(1)
            )
            .await
        );
    }
}
