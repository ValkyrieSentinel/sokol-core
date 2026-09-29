#!/usr/bin/env python3
"""Compile exact, isolated source fragments; no network/kernel effects or source changes."""
from pathlib import Path
import subprocess, tempfile, json, math
ROOT=Path(__file__).resolve().parents[4]
SHA='aeaf88bdbcb105c199347254a1a55e4cf25e56bc'
def source(path):
    return subprocess.check_output(['git','-C',str(ROOT),'show',f'{SHA}:{path}'],text=True)
main=source('orchestrator/src/main.rs')
assert main.count('atp_controller.try_consume(')==1
assert 'AtpBudgetController::new(10_000_000)' in main
assert 'atp_controller.reset();' in main
p2p=source('orchestrator/src/p2p.rs')
assert 'pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;' in p2p
assert 'const MAX_REPLAY_ENTRIES: usize = 100_000;' in p2p
start=p2p.index('#[derive(Default)]\npub struct ReplayGuard')
end=p2p.index('#[derive(Debug, Clone, PartialEq, Eq)]',start)
replay='use std::collections::HashMap;\nconst MAX_CLOCK_SKEW_MS:u64=30_000;\nconst MAX_REPLAY_ENTRIES:usize=100_000;\n'+p2p[start:end]
src=source('common/src/atp.rs')+'\nmod numerical_engine {\n'+source('orchestrator/src/sokol.rs')+'\n}\n'+replay+r'''
#[test] fn probe_tick_budget_cannot_throttle_single_charge() {
 let b=AtpBudgetController::new(10_000_000);
 for _ in 0..1000 { b.reset(); assert!(b.try_consume(250)); assert_eq!(b.remaining(),9_999_750); }
}
#[test] fn probe_relaxation_uses_retention_not_ewma_gain() {
 let actual=numerical_engine::SokolEngine::compute_relaxation_time(0.1).0;
 let ewma_tau=-1.0f64/(1.0f64-0.1).ln();
 assert!((actual-0.43429448).abs()<1e-7); assert!(ewma_tau>9.49);
}
#[test] fn probe_entropy_accepts_nonprobability_mass() {
 assert_eq!(numerical_engine::SokolEngine::compute_shannon_entropy(&[2.0]).0,-2.0);
}
#[test] fn probe_constant_rate_is_named_anomaly() {
 let e=numerical_engine::SokolEngine::new(500.0);
 for i in 1..10 { assert_eq!(e.detect_anomaly((i*600) as f64,((i-1)*600) as f64,1.0),Ok(true)); }
}
#[test] fn probe_full_replay_retains_expired_entries() {
 let mut r=ReplayGuard::default();
 r.seen=(0..100_000).map(|n| ((1,n),0)).collect();
 // At 30.001 seconds all timestamp=0 envelopes are stale at open(),
 // but the cache keeps them and refuses a fresh pair.
 assert!(!r.check_and_record(2,0,30_001,30_001));
 assert!(r.check_and_record(2,0,60_001,60_001));
}
'''
with tempfile.TemporaryDirectory(prefix='sokol-numeric-') as d:
 p=Path(d); (p/'probe.rs').write_text(src)
 rustc=str(Path.home()/'.cargo/bin/rustc')
 build=subprocess.run([rustc,'+stable','--edition=2021','--test',str(p/'probe.rs'),'-o',str(p/'probe')],capture_output=True,text=True)
 assert build.returncode==0,build.stderr
 run=subprocess.run([str(p/'probe'),'--test-threads=1'],capture_output=True,text=True)
 assert run.returncode==0,run.stdout+run.stderr
 print(json.dumps({'sha':SHA,'scope':'exact ATP, SokolEngine and ReplayGuard fragments, plus existing unit tests; not full node', 'build_stderr':build.stderr,'test_stdout':run.stdout,'exit':run.returncode,'derived':{'block_hit_bytes_per_possible_cpu':2*65536*8,'event_payload_bytes_per_sec_per_cpu':64*300,'event_ring_records_ideal_with_8_byte_header':262144//312,'event_retention_seconds_at_2000_per_sec':65536/2000,'frame_burst_seconds':5000/500,'byte_burst_seconds':32/4,'ipc_burst_seconds':5000/1000,'total_ipc_burst_seconds':20000/2000,'envelope_header':3+1+8+8+8+4,'snapshot_slack_bytes':128*1024-112*1024-32-3309,'ttl_first_capped_strike':1+math.ceil(math.log2(86400/900))}},indent=2))
