#!/usr/bin/env bash
# Verify a requested audit outcome using both the monitor exit code and path-bound label.
# Return 0 for the expected outcome, 1 for a verified contradiction, 2 for unverified.
audit_verdict() {
    local expected="${1:-}" path="${2:-}" output status actual
    case "$expected" in
        intact|broken) ;;
        *) printf 'UNVERIFIED audit: invalid expectation\n' >&2; return 2 ;;
    esac
    if [ -z "$path" ] || [ -z "${MONITOR_BIN:-}" ]; then
        printf 'UNVERIFIED audit: missing path or monitor executable\n' >&2
        return 2
    fi
    if output=$("$MONITOR_BIN" --verify "$path"); then
        status=0
    else
        status=$?
    fi
    # Both status and label must agree; unrelated exits and inconsistent output are unverified.
    case "$status:$output" in
        "0:OK $path:"*) actual=intact ;;
        "1:BROKEN $path:"*) actual=broken ;;
        *) printf 'UNVERIFIED audit: monitor failed or returned an inconsistent verdict\n' >&2; return 2 ;;
    esac
    [ "$expected" = "$actual" ]
}
