#!/usr/bin/env python3
"""Read exact prototype commits; compile diagnostic probes in a temporary directory.

Passing probes demonstrate limitations, not readiness. No original source is modified.
Run: python3 reproduce.py [--root /Users/s0fractal/Projects/external]
Requires locally available Git objects and a stable Rust toolchain; no downloads.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

BIO = "87fecc63ccfd717192de3e67e352416e44cd2ee4"
HW = "d1fea045bda0df5b857cb65ed46c0341cc0faf80"
BIO_PROBES = r'''
#[cfg(test)] mod transfer_probes {
    use super::*;
    fn pulse() -> BiophotonPulse {
        BiophotonPulse { magic: BiophotonPulse::MAGIC, content_hash: 1,
            threat_type: 3, stress_intensity: 255, phase: 0, emitter_id: 42 }
    }
    #[test] fn identical_replay_amplifies_energy() {
        let p = pulse(); let mut r = BiophotonReceptor::new(1.0, 0.1);
        assert!(r.absorb(p.as_bytes(), 1.0)); let first = r.current_energy();
        assert!(r.absorb(p.as_bytes(), 1.0));
        assert!(r.current_energy() > first * 3.9);
        assert_eq!(r.emitter_count, 1);
    }
    #[test] fn unsigned_neutralization_blacklists_a_named_emitter() {
        let mut p = pulse(); p.threat_type = 2;
        let mut r = BiophotonReceptor::new(1.0, 0.1);
        assert!(!r.absorb(p.as_bytes(), 1.0)); assert!(r.is_blacklisted(42));
        p.threat_type = 3; assert!(!r.absorb(p.as_bytes(), 1.0));
    }
    #[test] fn zero_distance_produces_nonfinite_state() {
        let mut r = BiophotonReceptor::new(1.0, 0.1);
        assert!(r.absorb(pulse().as_bytes(), 0.0));
        assert!(!r.current_energy().is_finite());
    }
    #[test] fn quiet_ticks_do_not_restore_stress() {
        let mut r = BiophotonReceptor::new(1.0, 0.5);
        let mut m = BioMetabolism::default();
        r.absorb(pulse().as_bytes(), 1.0); r.tick(&mut m);
        let stressed = m.stress_level; assert!(stressed > 0.0);
        for _ in 0..1000 { r.tick(&mut m); }
        assert!(r.current_energy() < 0.01); assert!(m.stress_level >= stressed);
    }
    #[test] fn content_hash_does_not_affect_reception() {
        let mut a = BiophotonReceptor::new(1.0, 0.1);
        let mut b = BiophotonReceptor::new(1.0, 0.1);
        let mut p = pulse(); a.absorb(p.as_bytes(), 1.0);
        p.content_hash = 65535; b.absorb(p.as_bytes(), 1.0);
        assert_eq!(a.current_energy(), b.current_energy());
    }
    #[test] fn polynomial_sine_has_large_pi_error() {
        assert!(no_std_sin(core::f32::consts::PI).abs() > 0.5);
    }
}
'''
HW_PROBES = r'''
#[cfg(test)] mod transfer_probes {
    use super::*;
    #[test] fn empty_and_bit_zero_select_the_same_decision() {
        let mut table = [0u8; 64]; table[0] = 7;
        assert_eq!(QuantumStateVector::EMPTY.collapse(&table), 7);
        assert_eq!(QuantumStateVector(1).collapse(&table), 7);
    }
    #[test] fn lowest_bit_wins_regardless_of_semantic_priority() {
        let mut table = [0u8; 64]; table[0] = 7; table[63] = 9;
        assert_eq!(QuantumStateVector(1 | (1u64 << 63)).collapse(&table), 7);
    }
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/Users/s0fractal/Projects/external"))
    args = parser.parse_args()
    results = []
    def run(cmd, expected=0, contains=None):
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
        ok = p.returncode == expected and (contains is None or contains in p.stderr)
        results.append(dict(command=[str(x) for x in cmd], exit=p.returncode,
                            expected_exit=expected, matched=ok, stdout=p.stdout, stderr=p.stderr))
        if not ok:
            raise RuntimeError(json.dumps(results[-1], indent=2))
    with tempfile.TemporaryDirectory(prefix="sokol-transfer-") as tmp:
        tmp = Path(tmp)
        run(["rustc", "+stable", "--version", "--verbose"])
        for name, sha, probes in [("sokol-biophoton", BIO, BIO_PROBES),
                                  ("sokol-hardware-filter", HW, HW_PROBES)]:
            original = subprocess.check_output(["git", "-C", str(args.root/name), "show",
                                                f"{sha}:src/lib.rs"], text=True)
            src = tmp / (name + ".rs")
            src.write_text(original + "\n" + probes)
            binary = tmp / name
            run(["rustc", "+stable", "--edition=2021", "--test", str(src), "-o", str(binary)])
            run([str(binary), "--test-threads=1"])
            if name == "sokol-hardware-filter":
                src.write_text(original)
                lib = tmp / "libhardware.rlib"
                run(["rustc", "+stable", "--edition=2021", "--crate-name=hardware",
                     "--crate-type=rlib", str(src), "-o", str(lib)])
                consumer = tmp / "consumer.rs"
                consumer.write_text('fn main() { println!("{}", hardware::QuantumStateVector::EMPTY.0); }\n')
                run(["rustc", "+stable", "--edition=2021", str(consumer), "--extern",
                     f"hardware={lib}", "-o", str(tmp/"consumer")], 1, "duplicate lang item")
    print(json.dumps(dict(biophoton=BIO, hardware=HW, results=results), indent=2))

if __name__ == "__main__":
    main()
