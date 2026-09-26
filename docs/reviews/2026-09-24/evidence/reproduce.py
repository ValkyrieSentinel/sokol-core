#!/usr/bin/env python3
"""Run review probes against current sources; substitutes only Aya map I/O.
No kernel attach, network configuration, or production source edits.
"""
import pathlib, tempfile, subprocess, hashlib, json, shutil
repo = pathlib.Path(__file__).resolve().parents[4]
out = pathlib.Path(__file__).resolve().parent
work = pathlib.Path(tempfile.mkdtemp(prefix='sokol-review-'))
(work / 'src').mkdir()
manifest = '''[package]
name = "sokol-review-probes"
version = "0.0.0"
edition = "2021"
[dependencies]
ipnet = "2.9"
log = "0.4"
tokio = { version = "1", features = ["full"] }
common = { path = COMMON }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive", "env"] }
env_logger = "0.10"
ureq = { version = "2", default-features = false }
axum = "0.7"
sysinfo = "0.39"
futures-util = "0.3"
chrono = "0.4"
rand = "0.8"
tower = { version = "0.5", features = ["util"] }
anyhow = "1"
bincode = "1.3"
pqcrypto-dilithium = "0.5"
pqcrypto-traits = "0.3.5"
blake3 = "1.5"
'''.replace('COMMON', json.dumps(str(repo / 'common')))
for name in ['sokol-operator', 'sokol-suricata', 'sokol-crowdsec', 'sokol-fastnetmon-notify']:
    manifest += '\n[[bin]]\nname = ' + json.dumps(name) + '\npath = ' + json.dumps(str(repo / 'orchestrator/src/bin' / (name + '.rs'))) + '\n'
(work / 'Cargo.toml').write_text(manifest)
saved_lock = out / 'harness-Cargo.lock'
shutil.copy(saved_lock if saved_lock.exists() else repo / 'Cargo.lock', work / 'Cargo.lock')
source = (repo / 'orchestrator/src/block_table.rs').read_text()
source = source.replace('use aya::', 'use crate::mock_aya::')
source += r'''
#[cfg(test)] mod review_probes {
    use super::*;
    fn table() -> BlockTable { BlockTable::new(LpmTrie::default(), LpmTrie::default(), TtlPolicy {base: Duration::from_secs(60), max: Duration::from_secs(600)}) }
    #[test] fn failed_sync_poison_prevents_retry() {
        let mut t = table(); let ip = parse_target("198.51.100.8").unwrap(); let now = Instant::now();
        t.v4.fail_insert = true;
        assert!(t.insert_until(ip, Duration::from_secs(60), now).is_err());
        assert_eq!(t.active(), 1, "phantom active entry");
        t.v4.fail_insert = false;
        assert_eq!(t.insert_until(ip, Duration::from_secs(60), now).unwrap(), false);
        assert_eq!(t.v4.insert_calls, 1, "second sync did not even retry insertion");
        assert!(t.v4.entries.is_empty());
    }
    #[test] fn failed_expiry_is_reported_as_removed_and_not_retried() {
        let mut t = table(); let ip = parse_target("198.51.100.8").unwrap(); let now = Instant::now();
        t.insert(ip, Lifetime::Dynamic, now).unwrap(); t.v4.fail_remove = true;
        assert_eq!(t.expire(now + Duration::from_secs(61)), vec![ip]);
        assert_eq!(t.active(), 0); assert_eq!(t.v4.entries.len(), 1);
        t.v4.fail_remove = false;
        assert!(t.expire(now + Duration::from_secs(62)).is_empty());
        assert_eq!(t.v4.entries.len(), 1, "kernel entry remains orphaned");
    }
}
'''
(work / 'src/block_table.rs').write_text(source)
shutil.copy(repo / 'orchestrator/src/flowspec.rs', work / 'src/flowspec.rs')
(work / 'src/lib.rs').write_text(r'''
#![allow(dead_code)]
mod mock_aya {
 pub mod maps {
  pub mod lpm_trie {
   #[derive(Hash, PartialEq, Eq, Clone)] pub struct Key<K> { pub prefix:u32, pub key:K }
   impl<K> Key<K> { pub fn new(prefix:u32,key:K)->Self {Self{prefix,key}} }
  }
  #[derive(Debug)] pub struct MapError;
  pub struct MapData;
  pub struct LpmTrie<M,K: Eq+std::hash::Hash,V> {
   pub entries: std::collections::HashMap<lpm_trie::Key<K>,V>, pub fail_insert:bool, pub fail_remove:bool,
   pub insert_calls:usize, marker:std::marker::PhantomData<M>
  }
  impl<M,K:Eq+std::hash::Hash,V> Default for LpmTrie<M,K,V> {
   fn default()->Self {Self{entries:Default::default(),fail_insert:false,fail_remove:false,insert_calls:0,marker:Default::default()}}
  }
  impl<M,K:Eq+std::hash::Hash+Clone,V> LpmTrie<M,K,V> {
   pub fn insert(&mut self,k:&lpm_trie::Key<K>,v:V,_flags:u64)->Result<(),MapError> {
    self.insert_calls+=1; if self.fail_insert {return Err(MapError)} self.entries.insert(k.clone(),v);Ok(())
   }
   pub fn remove(&mut self,k:&lpm_trie::Key<K>)->Result<(),MapError> {
    if self.fail_remove {return Err(MapError)} self.entries.remove(k).map(|_|()).ok_or(MapError)
   }
  }
 }
}
mod block_table;
mod flowspec;
#[cfg(test)] mod probes {
 use super::*;
 use common::audit_log::{AuditLog,verify_chain};
 #[test] fn two_audit_writers_corrupt_chain() {
  let path = std::env::temp_dir().join(format!("sokol-probe-two-writers-{}.log",std::process::id()));
  let mut a=AuditLog::open(&path).unwrap(); let mut b=AuditLog::open(&path).unwrap();
  a.append(b"first").unwrap(); b.append(b"second").unwrap(); a.sync().unwrap(); b.sync().unwrap();
  assert!(verify_chain(&path).is_err()); drop(a);drop(b);std::fs::remove_file(path).unwrap();
 }
 #[test] fn flowspec_forgets_surviving_rules_on_restart() {
  let ip=block_table::parse_target("198.51.100.8").unwrap();
  let mut before=flowspec::Reconciler::default(); before.announced(ip);
  assert_eq!(before.plan(&Default::default()).1,vec![ip]);
  let after=flowspec::Reconciler::default();
  assert!(after.plan(&Default::default()).1.is_empty());
 }
 #[test] fn flowspec_does_not_notice_daemon_losing_rib() {
  let ip=block_table::parse_target("198.51.100.8").unwrap();
  let mut r=flowspec::Reconciler::default(); r.announced(ip);
  // No API takes observed RIB state; loss of remote rule cannot affect this plan.
  assert_eq!(r.plan(&[ip].into_iter().collect()),(vec![],vec![]));
 }
 #[tokio::test] async fn timed_out_gobgp_process_continues() {
  let marker=std::env::temp_dir().join(format!("sokol-late-gobgp-{}",std::process::id()));
  let cli=flowspec::GobgpCli{bin:"/bin/sh".into(),args:vec!["-c".into(),format!("sleep 6; touch '{}'",marker.display())]};
  assert!(cli.apply(true,block_table::parse_target("198.51.100.8").unwrap()).await.is_err());
  tokio::time::sleep(std::time::Duration::from_secs(2)).await;
  assert!(marker.exists(),"child performed its side effect after timeout");std::fs::remove_file(marker).unwrap();
 }
}
''')
# Import the real P2P implementation and the protocol declarations it consumes.
shutil.copy(repo / 'orchestrator/src/p2p.rs', work / 'src/p2p.rs')
mesh = (repo / 'orchestrator/src/mesh_sync.rs').read_text()
declarations = mesh[mesh.index('#[derive'):mesh.index('/// Entries per BlockSync')]
with (work / 'src/lib.rs').open('a') as f:
    f.write('\nuse serde::{Serialize,Deserialize};\n' + declarations + '\nmod p2p;\n')
inputs = ['orchestrator/src/block_table.rs','orchestrator/src/flowspec.rs','common/src/audit_log.rs','orchestrator/src/p2p.rs','orchestrator/src/mesh_sync.rs'] + ['orchestrator/src/bin/'+n+'.rs' for n in ['sokol-operator','sokol-suricata','sokol-crowdsec','sokol-fastnetmon-notify']]
(out / 'source-hashes.json').write_text(json.dumps({p:hashlib.sha256((repo/p).read_bytes()).hexdigest() for p in inputs},indent=2)+'\n')
print('Isolated harness:', work, flush=True)
with (out / 'probe-results.txt').open('w') as f:
    result = subprocess.run(['cargo','test','--manifest-path',str(work/'Cargo.toml')] + (['--locked'] if saved_lock.exists() else []) + ['--','--nocapture'],cwd=repo,stdout=f,stderr=subprocess.STDOUT)
shutil.copy(work / 'Cargo.lock', out / 'harness-Cargo.lock')
print((out / 'probe-results.txt').read_text())
raise SystemExit(result.returncode)
