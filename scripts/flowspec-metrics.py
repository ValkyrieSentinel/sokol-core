#!/usr/bin/env python3
"""Bounded HTTP smoke check of one coherent FlowSpec metric response."""
import math
import sys
import time
import urllib.request

NAMES = ("sokol_flowspec_enabled", "sokol_flowspec_readback_ok",
         "sokol_flowspec_announced", "sokol_flowspec_readback_age_seconds",
         "sokol_flowspec_discard_rules", "sokol_flowspec_round_converged",
         "sokol_flowspec_round_progress")


def matches(text, state, count, minimum_age):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if fields[0] in NAMES:
            if len(fields) != 2 or fields[0] in values:
                raise ValueError("malformed or duplicate FlowSpec sample")
            values[fields[0]] = float(fields[1])
    if set(values) != set(NAMES) or not all(math.isfinite(v) for v in values.values()):
        raise ValueError("missing or nonfinite FlowSpec sample")
    enabled, ok, observed, age, discard, converged, progress = (values[name] for name in NAMES)
    if enabled not in (0, 1) or ok not in (0, 1) or converged not in (0, 1) or observed < 0 or not observed.is_integer():
        raise ValueError("invalid FlowSpec state/count")
    if discard < 0 or not discard.is_integer() or discard > observed:
        raise ValueError("invalid FlowSpec discard count")
    if age < 0 and age != -1 or ok == 1 and (enabled != 1 or age < 0):
        raise ValueError("invalid FlowSpec age/status")
    if converged == 1 and (enabled != 1 or ok != 1 or age < 0 or discard != observed):
        raise ValueError("unverified FlowSpec convergence")
    if progress not in (-1, 0, 1):
        raise ValueError("invalid FlowSpec progress")
    if progress != -1 and (enabled != 1 or ok != 1 or age < 0):
        raise ValueError("unverified FlowSpec progress")
    if state == "disabled":
        return (enabled, ok, observed, age, discard, converged, progress) == (0, 0, 0, -1, 0, 0, -1)
    if state not in ("ok", "failed", "converged"):
        raise ValueError("invalid expectation")
    return (enabled == 1 and ok == (state != "failed") and observed == count
            and discard == count and age >= minimum_age
            and (state != "converged" or converged == 1))


def main():
    url, state, count, minimum_age = sys.argv[1:]
    # Eight seconds is a smoke wait limit, not a production freshness policy.
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                text = response.read().decode("utf-8")
            if matches(text, state, int(count), float(minimum_age)):
                return 0
        except (OSError, ValueError) as error:
            print(f"unverified FlowSpec metrics: {error}", file=sys.stderr)
            return 2
        time.sleep(0.1)
    print("FlowSpec metric expectation not observed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
