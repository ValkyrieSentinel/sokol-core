#!/usr/bin/env bash
# XDP smoke readback for the pinned GoBGP text CLI. Status: 0 confirmed expectation,
# 1 successful read contradicts expectation, 2 unverified (tool/read failure).
# No ownership/community or global network-state guarantee is inferred from this check.
flowspec_rule() {
    local expected="${1:-}" prefix="${2:-}" rib
    case "$expected" in
        present|absent) ;;
        *) printf 'UNVERIFIED FlowSpec: invalid expectation\n' >&2; return 2 ;;
    esac
    if [ -z "$prefix" ]; then
        printf 'UNVERIFIED FlowSpec: missing source prefix\n' >&2
        return 2
    fi
    # Require the producer's success before using any stdout, even a matching partial RIB.
    if ! rib=$(gobgp -p 50052 global rib -a ipv4-flowspec); then
        printf 'UNVERIFIED FlowSpec: cannot read upstream RIB\n' >&2
        return 2
    fi
    # Bash matches the quoted prefix literally; no matcher subprocess or redirection
    # can fail and impersonate a successful no-match result.
    case "$rib" in
        *"source: $prefix]"*) [ "$expected" = present ] ;;
        *) [ "$expected" = absent ] ;;
    esac
}

# BGP propagation is asynchronous. Retry a known contradictory RIB, never an
# unverified read. Bounded attempts; CLI/scheduler time is outside the sleep sum.
wait_flowspec_rule() {
    local attempt status
    for ((attempt = 0; attempt < 20; attempt++)); do
        if flowspec_rule "$@"; then return 0; else status=$?; fi
        [ "$status" -eq 1 ] || return "$status"
        if [ "$attempt" -lt 19 ]; then
            sleep 0.25 || return 2
        fi
    done
    return 1
}
