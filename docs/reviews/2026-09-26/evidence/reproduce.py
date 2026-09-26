#!/usr/bin/env python3
"""Read pinned Git sources; exercise current domain/transport with map I/O stubbed.
All probes assert the observed defect, not the desired fixed behavior.
"""
import pathlib, subprocess, tempfile, json, hashlib
repo=pathlib.Path(__file__).resolve().parents[4]
out=pathlib.Path(__file__).resolve().parent
commit='5fbacdc7c7af94be0ac1e58262af381f8e9fdb0c'
work=pathlib.Path(tempfile.mkdtemp(prefix='sokol-review-0926-'))
archive=subprocess.Popen(['git','archive',commit],cwd=repo,stdout=subprocess.PIPE)
subprocess.run(['tar','-x','-C',str(work)],stdin=archive.stdout,check=True)
assert archive.wait()==0
h=work/'review-harness';(h/'src').mkdir(parents=True)
manifest='''[package]
name="sokol-review-0926"
version="0.0.0"
edition="2021"
[workspace]
[dependencies]
common={path="../common"}
ipnet="2.9"
serde={version="1",features=["derive"]}
serde_json="1"
blake3="1.5"
log="0.4"
tokio={version="1",features=["full"]}
anyhow="1"
bincode="1.3"
pqcrypto-dilithium="0.5"
pqcrypto-traits="0.3.5"
rand="0.8"
'''
(h/'Cargo.toml').write_text(manifest)
lock=out/'Cargo.lock'
(h/'Cargo.lock').write_bytes((lock if lock.exists() else work/'Cargo.lock').read_bytes())
source=(work/'orchestrator/src/block_table.rs').read_text().replace('use aya::','use crate::mock_aya::')
source=source.rstrip()[:-1]+r'''
    #[test] fn review_retractions_never_expire() {
        let mut t=table(1,64);let id="a".repeat(64);
        t.retract(2,&[id.clone()],T0);
        assert_eq!(t.retractions[&id].forget_ms,None);
        t.tick(T0+ms(POLICY.max)*100);
        assert!(t.retractions.contains_key(&id));
    }
    #[test] fn review_duplicate_delivery_escalates_one_event() {
        let mut t=table(1,64);
        let a=t.add_local(ip("198.51.100.8"),ClaimKind::Detector,"same SIGNAL",T0);
        let b=t.add_local(ip("198.51.100.8"),ClaimKind::Detector,"same SIGNAL",T0+1);
        assert_eq!(a.ttl,Some(Duration::from_secs(60)));
        assert_eq!(b.ttl,Some(Duration::from_secs(120)));
        assert_ne!(a.claim.id(),b.claim.id());
    }
    #[test] fn review_replayed_capped_claim_gets_new_lease_after_restart() {
        let mut origin=table(2,64);
        let mut c=detect(&mut origin,"198.51.100.8",T0);c.expires_ms=None;
        let mut a=table(1,64);a.adopt(c.clone(),true,T0);a.tick(T0+ms(POLICY.max)+1);
        assert!(!a.is_blocked(ip(&c.target)));
        let persisted=a.take_persisted(T0+ms(POLICY.max)+1);
        let mut b=table(1,64);b.restore(persisted,|_|true,T0+ms(POLICY.max)+1);
        assert_eq!(b.adopt(c,true,T0+ms(POLICY.max)+1),Adoption::Enforced);
    }
    #[test] fn review_expired_targets_bypass_retry_budget() {
        struct Count { deletes:usize }
        impl Blocklist for Count {
            fn add(&mut self,_:IpNet)->Result<(),MapError>{Ok(())}
            fn delete(&mut self,_:IpNet)->Result<(),MapError>{self.deletes+=1;Err(MapError::ElementNotFound)}
        }
        let mut t=BlockTable::with_lists(Count{deletes:0},POLICY,1);
        for i in 0..300 {t.adopt(Claim{issuer:2,kind:ClaimKind::Detector,target:format!("198.51.{}.{}",i/256,i%256),issued_ms:T0,expires_ms:None,reason:"x".into()},true,T0);}
        t.tick(T0+ms(POLICY.max)+1);t.lists.deletes=0;
        t.tick(T0+ms(POLICY.max)+2);
        assert_eq!(t.lists.deletes,300,"second tick still bypasses the 256 retry budget");
    }
    #[test] fn review_local_claims_ignore_known_claim_limit() {
        let mut t=table(1,1);
        for i in 0..MAX_KNOWN_CLAIMS+1 {t.add_local(ip("198.51.100.8"),ClaimKind::Detector,"repeat",T0+i as u64);}
        assert_eq!(t.claims.len(),MAX_KNOWN_CLAIMS+1);
        assert_eq!(t.active(),1);
    }
}
'''
(h/'src/block_table.rs').write_text(source)
(h/'src/p2p.rs').write_bytes((work/'orchestrator/src/p2p.rs').read_bytes())
mesh=(work/'orchestrator/src/mesh_sync.rs').read_text()
declarations=mesh[mesh.index('#[derive'):mesh.index('impl MeshCommand {\n    pub fn telemetry_record')]
lib=r'''
#![allow(dead_code)]
use serde::{Serialize,Deserialize};
mod mock_aya { pub mod maps {
 pub mod lpm_trie {pub struct Key<K>(pub u32,pub K);impl<K> Key<K>{pub fn new(p:u32,k:K)->Self{Self(p,k)}}}
 #[derive(Debug)] pub enum MapError {OutOfBounds{index:u32,max_entries:u32},ElementNotFound,KeyNotFound}
 pub struct MapData;pub struct LpmTrie<M,K,V>(std::marker::PhantomData<(M,K,V)>);
 impl<M,K,V> LpmTrie<M,K,V> {
  pub fn insert(&mut self,_:&lpm_trie::Key<K>,_:V,_:u64)->Result<(),MapError>{unreachable!("real kernel adapter not exercised")}
  pub fn remove(&mut self,_:&lpm_trie::Key<K>)->Result<(),MapError>{unreachable!("real kernel adapter not exercised")}
 }
}}
mod block_table;
use block_table::{Claim,ClaimId};
mod mesh_sync {pub use crate::AlertLevel;}
mod p2p;
'''+declarations+r'''
#[cfg(test)] mod review {
 use super::*;use block_table::*;use std::collections::HashSet;use std::time::Duration;
 use tokio::sync::Mutex;use std::sync::Arc;
 #[derive(Default)] struct Maps(HashSet<ipnet::IpNet>);
 impl Blocklist for Maps {
  fn add(&mut self,n:ipnet::IpNet)->Result<(),mock_aya::maps::MapError>{self.0.insert(n);Ok(())}
  fn delete(&mut self,n:ipnet::IpNet)->Result<(),mock_aya::maps::MapError>{self.0.remove(&n);Ok(())}
 }
 #[tokio::test] async fn review_one_signed_snapshot_forges_quorum() {
  let key=p2p::NodeCrypto::generate();let mut trust=p2p::TrustStore::default();trust.insert(2,key.public_key);
  let registry=p2p::PeerRegistry::new(trust);
  let now=p2p::now_ms();let net=parse_target("198.51.96.0/20").unwrap();
  let claims=[3,4].into_iter().map(|issuer|Claim{issuer,kind:ClaimKind::Detector,target:show(&net),issued_ms:now,expires_ms:Some(now+60000),reason:"fabricated by node 2".into()}).collect();
  let cmd=MeshCommand::BlockSync{issuer:2,claims,retracted:vec![]};
  let env=p2p::seal(&key,2,&p2p::NetworkMessage::Command(cmd),&Arc::new(Mutex::new(p2p::DagTracker::new()))).await.unwrap();
  use tokio::io::AsyncWriteExt;
  let (tx,mut rx)=tokio::sync::mpsc::channel(8);
  let (_shutdown,shutdown_rx)=tokio::sync::watch::channel(false);
  let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr=listener.local_addr().unwrap();
  let server=p2p::P2PNetwork::new(addr,1,Arc::new(p2p::NodeCrypto::generate()),Arc::new(Mutex::new(p2p::DagTracker::new())),tx,8,shutdown_rx,registry);
  let task=tokio::spawn(async move {server.serve(listener).await});
  let mut stream=tokio::net::TcpStream::connect(addr).await.unwrap();
  let hello=p2p::seal(&key,2,&p2p::NetworkMessage::Handshake{node_id:2},&Arc::new(Mutex::new(p2p::DagTracker::new()))).await.unwrap();
  for e in [hello,env] {let bytes=bincode::serialize(&e).unwrap();stream.write_all(&(bytes.len() as u32).to_be_bytes()).await.unwrap();stream.write_all(&bytes).await.unwrap();}
  let cmd=tokio::time::timeout(Duration::from_secs(2),rx.recv()).await.unwrap().unwrap();
  assert_eq!(cmd.claimed_sender(),Some(2));
  task.abort();
  let mut table=BlockTable::with_lists(Maps::default(),TtlPolicy{base:Duration::from_secs(60),max:Duration::from_secs(600)},1);
  table.configure_peers(Envelope::unlimited(Duration::from_secs(600)),Default::default(),Quorum{k:2,wide_v4:24,wide_v6:64},now);
  if let MeshCommand::BlockSync{claims,..}=cmd {for c in claims {table.adopt(c,true,now);}}
  assert!(table.is_blocked(net),"one pinned key invented two unpinned voters");
 }
 #[tokio::test] async fn review_snapshot_tombstones_exceed_frame_limit() {
  let key=p2p::NodeCrypto::generate();let cmd=MeshCommand::BlockSync{issuer:1,claims:vec![],retracted:(0..2000).map(|i|format!("{i:064x}")).collect()};
  let env=p2p::seal(&key,1,&p2p::NetworkMessage::Command(cmd),&Arc::new(Mutex::new(p2p::DagTracker::new()))).await.unwrap();
  let size=bincode::serialize(&env).unwrap().len();println!("review snapshot envelope bytes={size}, max=131072");assert!(size>128*1024);
 }
 #[test] fn review_hash_does_not_authenticate_issuer() {
  let c=Claim{issuer:999,kind:ClaimKind::Detector,target:"198.51.100.8".into(),issued_ms:0,expires_ms:None,reason:"x".into()};assert_eq!(c.id().len(),64);
 }
}
'''
(h/'src/lib.rs').write_text(lib)
print('Pinned source:',commit,'harness:',h,flush=True)
with (out/'results.txt').open('w') as f:
 result=subprocess.run(['cargo','test','--manifest-path',str(h/'Cargo.toml')]+(['--locked'] if lock.exists() else [])+['--','--nocapture'],cwd=work,stdout=f,stderr=subprocess.STDOUT)
lock.write_bytes((h/'Cargo.lock').read_bytes())
(out/'sources.json').write_text(json.dumps({'commit':commit,'sha256':{str(p.relative_to(work)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (work/'orchestrator/src').rglob('*.rs')}},indent=2)+'\n')
print((out/'results.txt').read_text()[-9000:])
raise SystemExit(result.returncode)
