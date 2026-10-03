#!/usr/bin/env bash
# XDP smoke readback for the pinned GoBGP text CLI. Status: 0 confirmed expectation,
# 1 successful read contradicts expectation, 2 unverified (tool/read/matcher failure).
# No ownership/community or global network-state guarantee is inferred from this check.
flowspec_rule() {
    local expected="${1:-}" prefix="${2:-}" rib match_status
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
    if grep -Fq -- "source: $prefix]" <<<"$rib"; then
        match_status=0
    else
        match_status=$?
    fi
    case "$match_status" in
        0) [ "$expected" = present ] ;;
        1) [ "$expected" = absent ] ;;
        *) printf 'UNVERIFIED FlowSpec: RIB matcher failed\n' >&2; return 2 ;;
    esac
}
