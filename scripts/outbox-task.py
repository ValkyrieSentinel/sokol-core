#!/usr/bin/env python3
"""Bounded read-only context for IPC-A1; it never runs tests or signs a manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ("docs/INVARIANTS.md", "docs/witness-manifest.json", "docs/witness-manifest.json.sig",
          ".github/witness-signers", "orchestrator/src/delivery.rs", "scripts/check-delivery.sh",
          "scripts/stargate_delivery_probe.rs", ".github/workflows/stargate-shadow.yml",
          "scripts/witness-pin.py", "scripts/outbox-task.py")
SCOPE = "Read-only IPC-A1 work context. Declared obligations and known bytes are not proof of execution, signature validity, helper closure, acceptance or kernel enforcement. Native result UNKNOWN. No imported recipes execute."


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def read(root, name):
    path = root / name
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("Symlink input refused")
    with path.open("rb") as stream:
        value = stream.read(2_097_153)
    if len(value) > 2_097_152:
        raise ValueError("Input exceeds bound")
    return value


def snapshot(root):
    return {name: hashlib.sha256(read(root, name)).hexdigest() for name in INPUTS}


def packet(root, budget=8192, since=None):
    if type(budget) is not int or not 2048 <= budget <= 65536:
        raise ValueError("Budget must be 2048..65536 bytes")
    before = snapshot(root)
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True, timeout=5).stdout.strip()
    lines = read(root, "docs/INVARIANTS.md").decode().splitlines()
    rows = [line for line in lines if line.startswith("| IPC-A1 |")]
    if len(rows) != 1:
        raise ValueError("Missing or ambiguous IPC-A1")
    manifest = json.loads(read(root, "docs/witness-manifest.json"))
    pin = manifest["rows"]["IPC-A1"]
    if not isinstance(pin["witnesses"], list) or not pin["witnesses"]:
        raise ValueError("Missing pinned witnesses")
    body = {"profile": "sokol.agent.outbox-task.v1", "base_commit": base,
            "known_inputs": before, "contract_id": "IPC-A1", "declared_row": rows[0],
            "pinned_statement_hash": pin["statement"], "pinned_witnesses": pin["witnesses"],
            "binding": "DECLARED_CONTRACT_AND_UNVERIFIED_OWNER_PIN",
            "signature_validity": "NOT_CHECKED", "current_native_result": "UNKNOWN",
            "native_execution_this_request": "NONE", "read_only_git_query": "rev-parse HEAD",
            "editable_owner": "orchestrator/src/delivery.rs implementation; existing witnesses remain unchanged",
            "objective": "Reproduce an IPC-A1 counterexample or add a discriminating regression without weakening preserved witnesses",
            "acceptance": "NOT_ESTABLISHED",
            "stop_conditions": ["Changing a pinned witness/statement requires owner re-pin",
                                "New blocking authority, ACK semantics or durable-delivery promise requires a separate decision",
                                "No reproduced defect is not permission for arbitrary implementation changes"],
            "verification": [
                {"command": "scripts/check-delivery.sh", "scope": "Actual std-only Outbox tests and socket probe; works without Linux/XDP"},
                {"command": "python3 scripts/witness-pin.py check", "scope": "Owner signature and preserved witness-body correspondence; helper closure excluded"},
                {"workflow": ".github/workflows/stargate-shadow.yml", "scope": "Linux CI plus pinned Stargate shadow models/traces, not full-system proof"}],
            "unknowns": ["Current native observations", "Signature validity until explicit check", "Helpers are not owner-pinned",
                         "Exactly-once delivery, durable outbox and completed kernel effect are not established"],
            "scope": SCOPE}
    value = {"id": "sha256:" + hashlib.sha256(b"sokol.agent.outbox-task.v1\0" + encode(body)).hexdigest(), "body": body}
    if len(encode(value)) > budget:
        raise ValueError("Essential context exceeds budget")
    after_base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                                capture_output=True, text=True, timeout=5).stdout.strip()
    if snapshot(root) != before or base != after_base:
        raise ValueError("Inputs moved during projection")
    if since == value["id"]:
        return {"id": value["id"], "status": "UNCHANGED", "current_native_result": "UNKNOWN", "scope": SCOPE}
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--budget", type=int, default=8192)
    parser.add_argument("--since")
    args = parser.parse_args()
    try:
        print(encode(packet(ROOT, args.budget, args.since)).decode())
        return 0
    except (ValueError, KeyError, OSError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "REFUSED", "current_native_result": "UNKNOWN", "reason": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
