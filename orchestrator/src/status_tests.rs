use super::metrics::{self, Snapshot, WorkerHealth, WorkerState};
use super::p2p::{NodeCrypto, P2PNetwork, PeerRegistry, TrustStore};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

#[test]
fn a_status_snapshot_never_invents_freshness_before_observation_or_after_expiry() {
    let now = Instant::now();
    assert_eq!(
        metrics::status_at(&Snapshot::default(), now)["freshness"],
        "UNKNOWN"
    );
    let mut snapshot = Snapshot {
        sampled_at: Some(now),
        p2p_expected: 3,
        p2p_peers: 1,
        blocks_pending: 2,
        blocks_active_v4: 7,
        audit_healthy: true,
        ..Default::default()
    };
    let fresh = metrics::status_at(&snapshot, now + Duration::from_secs(5));
    assert_eq!(fresh["freshness"], "FRESH");
    assert_eq!(fresh["configured"]["expected_mesh_peers"], 3);
    assert_eq!(fresh["observed"]["connected_peers"], 1);
    assert_eq!(fresh["desired"]["pending_kernel_updates"], 2);
    assert_eq!(fresh["applied"]["kernel_blocks_v4"], 7);
    assert_eq!(
        metrics::status_at(&snapshot, now + Duration::from_millis(5001))["freshness"],
        "STALE"
    );
    snapshot.sampled_at = Some(now + Duration::from_secs(1));
    assert_eq!(metrics::status_at(&snapshot, now)["freshness"], "UNKNOWN");
}

#[test]
fn worker_states_have_one_bounded_shared_observation() {
    let health = WorkerHealth::default();
    let observer = health.clone();
    assert_eq!(observer.get(), 0);
    for (state, expected) in [
        (WorkerState::Running, 1),
        (WorkerState::Failed, 2),
        (WorkerState::Stopped, 3),
        (WorkerState::Unknown, 0),
    ] {
        health.set(state);
        assert_eq!(observer.get(), expected);
    }
}

#[test]
fn configured_peers_and_worker_failure_are_exported_with_snapshot_age() {
    let mut snapshot = Snapshot {
        p2p_expected: 3,
        p2p_peers: 1,
        mesh_worker: 2,
        kernel_worker: 1,
        ..Default::default()
    };
    let unknown = metrics::render(&snapshot);
    assert!(unknown.contains("sokol_p2p_expected_peers 3\n"));
    assert!(unknown.contains("sokol_p2p_active_peers 1\n"));
    assert!(unknown.contains("sokol_worker_state{worker=\"mesh_listener\"} 2\n"));
    assert!(unknown.contains("sokol_worker_state{worker=\"kernel_events\"} 1\n"));
    assert!(unknown.contains("sokol_snapshot_age_seconds -1\n"));
    snapshot.sampled_at = Some(Instant::now() - Duration::from_secs(10));
    let text = metrics::render(&snapshot);
    let age: f64 = text
        .lines()
        .find_map(|line| line.strip_prefix("sokol_snapshot_age_seconds "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(age >= 10.0, "stale snapshot was refreshed: {age}");
}

#[tokio::test]
async fn a_failed_bind_and_orderly_stop_have_distinct_worker_states() {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health = WorkerHealth::default();
    let (sender, receiver) = mpsc::channel(1);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let make = |address| {
        P2PNetwork::new(
            address,
            1,
            Arc::new(NodeCrypto::generate()),
            sender.clone(),
            1,
            shutdown_rx.clone(),
            PeerRegistry::new(TrustStore::default()),
        )
        .with_health(health.clone())
    };
    assert!(make(occupied.local_addr().unwrap()).run().await.is_err());
    assert_eq!(health.get(), WorkerState::Failed as u8);
    health.set(WorkerState::Unknown);
    let net = make("127.0.0.1:0".parse().unwrap());
    let running = tokio::spawn(async move { net.run().await });
    tokio::time::timeout(Duration::from_secs(3), async {
        while health.get() != WorkerState::Running as u8 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    shutdown.send(true).unwrap();
    running.await.unwrap().unwrap();
    assert_eq!(health.get(), WorkerState::Stopped as u8);
    drop(receiver);
}
