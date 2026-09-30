"""Check forwarding of CrowdSec's remaining duration, not a wall-clock guess.

The smoke creates a five-minute decision. Polling consumes part of that interval.
Use Decimal arithmetic independent of the adapter's Rust floating-point parser.
"""
import argparse
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
import re

SCALES = {name: Decimal(scale) for name, scale in {
    'h': '3600', 'm': '60', 's': '1', 'ms': '.001',
    'us': '.000001', 'µs': '.000001', 'ns': '.000000001',
}.items()}
TOKEN = re.compile(r'([0-9]+(?:\.[0-9]+)?)(ms|us|µs|ns|h|m|s)')


def seconds(duration):
    total = Decimal(0)
    position = 0
    for match in TOKEN.finditer(duration):
        if match.start() != position:
            raise ValueError('invalid CrowdSec duration: ' + duration)
        total += Decimal(match[1]) * SCALES[match[2]]
        position = match.end()
    if position != len(duration) or not 0 < total <= 300:
        raise ValueError('remaining duration must be positive and at most five minutes')
    return int(total.to_integral_value(rounding=ROUND_CEILING))


def verify(adapter, node, address):
    ip = re.escape(address)
    duration = r'(?P<duration>[^)]+)'
    sent = list(re.finditer(
        r'SIGNAL#[0-9]+;ttl=(?P<ttl>[0-9]+):crowdsec\|' + ip +
        r'\|-\|sokol smoke ban \(origin cscli, crowdsec duration ' + duration + r'\)', adapter))
    enforced = list(re.finditer(
        r'Dynamic block enforced in XDP: ' + ip + r' for (?P<ttl>[0-9]+)s \| Reason: '
        r'crowdsec: sokol smoke ban \(origin cscli, crowdsec duration ' + duration + r'\)', node))
    if len(sent) != 1 or len(enforced) != 1:
        raise ValueError('expected exactly one matching sent decision and enforced block')
    sent, enforced = sent[0], enforced[0]
    expected = seconds(sent['duration'])
    if enforced['duration'] != sent['duration']:
        raise ValueError('node reason does not preserve the reported duration')
    if int(sent['ttl']) != expected or int(enforced['ttl']) != expected:
        raise ValueError(f'duration {sent["duration"]} requires {expected}s; '
                         f'adapter sent {sent["ttl"]}s, node enforced {enforced["ttl"]}s')
    return expected


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('adapter_log', type=Path)
    parser.add_argument('node_log', type=Path)
    parser.add_argument('address')
    args = parser.parse_args()
    try:
        ttl = verify(args.adapter_log.read_text(), args.node_log.read_text(), args.address)
    except ValueError as error:
        raise SystemExit(str(error))
    print(f'CrowdSec remaining duration: adapter and node both use {ttl}s')
