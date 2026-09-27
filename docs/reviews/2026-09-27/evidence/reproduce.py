#!/usr/bin/env python3
"""Pinned domain + transport tests; maps stubbed, no host network configuration changes.
Review probes assert counterexamples, NOT desired fixed behavior.
"""
import hashlib,json,pathlib,subprocess,tempfile
repo=pathlib.Path(__file__).resolve().parents[4]
out=pathlib.Path(__file__).resolve().parent
commit='98b5a5df4934ef88c923a9a2959176907bfeabba'
work=pathlib.Path(tempfile.mkdtemp(prefix='sokol-review-harness-0927-'))
a=subprocess.Popen(['git','archive',commit],cwd=repo,stdout=subprocess.PIPE)
subprocess.run(['tar','-x','-C',str(work)],stdin=a.stdout,check=True);assert a.wait()==0
h=work/'review-harness';(h/'src').mkdir(parents=True)
(h/'Cargo.toml').write_text('''[package]
name="sokol-review-0927"
version="0.0.0"
edition="2021"
[workspace]
[dependencies]
common={path="../common", features=["std"]}
ipnet="2.9"
serde={version="1",features=["derive"]}
serde_json="1"
blake3="1.5"
log="0.4"
tokio={version="1",features=["full"]}
anyhow="1"
ml-dsa="=0.1.1"
rand="0.8"
proptest={version="1",default-features=false,features=["std"]}
''')
lock=out/'Cargo.lock'
(h/'Cargo.lock').write_bytes((lock if lock.exists() else work/'Cargo.lock').read_bytes())
source=(work/'orchestrator/src/block_table.rs').read_text().replace('use aya::','use crate::mock_aya::')
source=source.rstrip()[:-1]+r'''
    #[test] fn review_restart_replays_event_and_extends_lease() {
        let mut a=table(1,64);
        assert!(a.first_sighting("crowdsec","17",T0));
        let first=detect(&mut a,"198.51.100.8",T0);
        let mut b=table(1,64);
        b.restore(a.take_persisted(T0+50*S), |_|true,T0+50*S);
        assert!(b.first_sighting("crowdsec","17",T0+50*S));
        let again=detect(&mut b,"198.51.100.8",T0+50*S);
        assert_eq!(first.expires_ms,Some(T0+60*S));
        assert_eq!(again.expires_ms,Some(T0+110*S));
        println!("R27 replay: same event lease end moved from {:?} to {:?}",first.expires_ms,again.expires_ms);
    }
}
'''
(h/'src/block_table.rs').write_text(source)
p2p=(work/'orchestrator/src/p2p.rs').read_text()+r'''
#[cfg(test)] mod review_probes {
 use super::*;
 fn path(tag:&str)->std::path::PathBuf {std::env::temp_dir().join(format!("review-{}-{}-{}",tag,std::process::id(),rand::random::<u64>()))}
 #[test] fn review_non_ascii_hex_panics() {
   let result=std::panic::catch_unwind(||parse_public_key("mldsa65:a€"));
   assert!(result.is_err(),"malformed UTF8-boundary input aborts instead of returning Err");
 }
 #[test] fn review_typo_prefix_accepted_as_legacy_and_clears_trust() {
   let p=path("peers");
   std::fs::write(&p,r#"[{"node_id":2,"public_key":"mldsa6S:garbage"}]"#).unwrap();
   let mut old=TrustStore::default();old.insert(2,NodeCrypto::generate().public_key);
   let registry=PeerRegistry::new(old);assert_eq!(registry.pinned_peers(),1);
   let candidate=TrustStore::load(&p).unwrap();
   assert_eq!(candidate.legacy_peers(),&[2]);
   assert_eq!(registry.reload(candidate),0);
   assert_eq!(registry.pinned_peers(),0);
   std::fs::remove_file(p).unwrap();
 }
 #[test] fn review_migration_overwrites_existing_retired_key() {
   let p=path("key");let retired=std::path::PathBuf::from(format!("{}.dilithium3.retired",p.display()));
   std::fs::write(&retired,b"previous recovery evidence").unwrap();
   std::fs::write(&p,vec![7u8;LEGACY_KEY_FILE_LEN]).unwrap();
   std::fs::set_permissions(&p,std::fs::Permissions::from_mode(0o600)).unwrap();
   NodeCrypto::load_or_create(&p).unwrap();
   assert_eq!(std::fs::read(&retired).unwrap(),vec![7u8;LEGACY_KEY_FILE_LEN]);
   assert_eq!(std::fs::read(&p).unwrap().len(),36);
   std::fs::remove_file(p).unwrap();std::fs::remove_file(retired).unwrap();
 }
}
'''
(h/'src/p2p.rs').write_text(p2p)
mesh=(work/'orchestrator/src/mesh_sync.rs').read_text()
declarations=mesh[mesh.index('#[derive'):mesh.index('impl MeshCommand {\n    pub fn telemetry_record')]
(h/'src/lib.rs').write_text(r'''
#![allow(dead_code)]
use serde::{Serialize,Deserialize};
mod mock_aya { pub mod maps {
 pub mod lpm_trie {pub struct Key<K>(pub u32,pub K);impl<K> Key<K>{pub fn new(p:u32,k:K)->Self{Self(p,k)}}}
 #[derive(Debug)] pub enum MapError {OutOfBounds{index:u32,max_entries:u32},ElementNotFound,KeyNotFound}
 pub struct MapData;pub struct LpmTrie<M,K,V>(std::marker::PhantomData<(M,K,V)>);
 impl<M,K,V> LpmTrie<M,K,V> {
  pub fn insert(&mut self,_:&lpm_trie::Key<K>,_:V,_:u64)->Result<(),MapError>{unreachable!("kernel adapter not exercised")}
  pub fn remove(&mut self,_:&lpm_trie::Key<K>)->Result<(),MapError>{unreachable!("kernel adapter not exercised")}
 }
}}
mod block_table;
use block_table::{Claim,ClaimId};
mod mesh_sync {pub use crate::{AlertLevel,pack_snapshot};}
mod p2p;
'''+declarations)
main_source=(work/'orchestrator/src/main.rs').read_text()
state_code=main_source[main_source.index('fn save_state('):main_source.index('struct IpcCtx {')]
state_prefix=r'''
#[cfg(test)] mod state_probe {
use std::sync::Arc;
use crate::block_table::{BlockTable,Persisted,TtlPolicy,Blocklist,ClaimKind,parse_target};
use crate::mock_aya::maps::MapError;
use crate::p2p::now_ms;
use std::time::Duration;
struct Maps;
impl Blocklist for Maps {
 fn add(&mut self,_:ipnet::IpNet)->Result<(),MapError>{Ok(())}
 fn delete(&mut self,_:ipnet::IpNet)->Result<(),MapError>{Ok(())}
}
type SharedBlockTable=Arc<tokio::sync::Mutex<BlockTable<Maps>>>;
'''
state_test=r'''
#[tokio::test] async fn review_blocked_state_write_has_no_deadline_or_unhealthy_signal() {
 let dir=std::env::temp_dir().join(format!("state-review-{}",rand::random::<u64>()));
 std::fs::create_dir(&dir).unwrap();
 let path=dir.join("state.json");let fifo=path.with_extension("tmp");
 assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
 let store=Arc::new(StateStore::new(path));
 let mut table=BlockTable::with_lists(Maps,TtlPolicy{base:Duration::from_secs(60),max:Duration::from_secs(600)},1);
 table.add_local(parse_target("198.51.100.8").unwrap(),ClaimKind::Operator,"test",now_ms()).unwrap();
 let blocks=Arc::new(tokio::sync::Mutex::new(table));
 let (s,b)=(store.clone(),blocks.clone());
 let mut writer=tokio::spawn(async move {s.persist(&b).await});
 assert!(tokio::time::timeout(Duration::from_millis(250),&mut writer).await.is_err());
 assert!(store.healthy(),"stalled writer still reports healthy");
 assert!(!blocks.lock().await.dirty(),"snapshot already taken");
 // Release our artificial blocked open; no background task or FIFO is left hanging.
 let drain=tokio::task::spawn_blocking(move || {use std::io::Read;let mut data=Vec::new();std::fs::File::open(fifo).unwrap().read_to_end(&mut data).unwrap();});
 let result=tokio::time::timeout(Duration::from_secs(5),writer).await.unwrap().unwrap();
 println!("R27 FIFO released; platform-specific completion: {:?}",result);
 drain.await.unwrap();std::fs::remove_dir_all(dir).unwrap();
}
}
'''
with (h/'src/lib.rs').open('a') as f:f.write(state_prefix+state_code+state_test)
print('Harness',h,flush=True)
with (out/'probes.txt').open('w') as f:
 r=subprocess.run(['cargo','test','--manifest-path',str(h/'Cargo.toml')]+(['--locked'] if lock.exists() else [])+['--','--nocapture'],cwd=work,stdout=f,stderr=subprocess.STDOUT)
if (h/'Cargo.lock').exists():lock.write_bytes((h/'Cargo.lock').read_bytes())
(out/'probes-status.json').write_text(json.dumps({'commit':commit,'exit':r.returncode,'sha256':{str(p.relative_to(work)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [work/'orchestrator/src/block_table.rs',work/'orchestrator/src/p2p.rs',work/'orchestrator/src/mesh_sync.rs']}},indent=2)+'\n')
print((out/'probes.txt').read_text()[-6500:]);raise SystemExit(r.returncode)
