"""Kernel verdict + live probe for this smoke's isolated IPv4 veth lab (XDP-S1)."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile


class Unverified(Exception):
    pass


def run(args, timeout=5):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, 'LC_ALL': 'C'})


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Unverified('duplicate JSON field')
        result[key] = value
    return result


def read_json(args):
    result = run(args)
    if result.returncode != 0:
        raise Unverified('kernel read/run command failed')
    return json.loads(result.stdout, object_pairs_hook=unique_object)


def attachment(interface):
    data = read_json(['bpftool', '-j', 'net', 'show', 'dev', interface])
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise Unverified('unrecognized attachment response')
    entries = data[0].get('xdp')
    if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
        raise Unverified('unrecognized XDP attachment list')
    selected = [e for e in entries if e.get('devname') == interface]
    if len(selected) != 1:
        raise Unverified('missing or ambiguous XDP attachment')
    entry = selected[0]
    if any(type(entry.get(k)) is not int or not 0 < entry[k] < 2**32 for k in ['id', 'ifindex']):
        raise Unverified('invalid XDP identity')
    if entry.get('mode') not in ['driver', 'generic']:
        raise Unverified('unsupported or multiple XDP attachments')
    return entry['id'], entry['ifindex'], entry['mode']


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def frame(source, destination, fragment):
    src, dst = ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed
    icmp = struct.pack('!BBHHH', 8, 0, 0, 123, 1) + bytes(56)
    icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), 123,
                     0x2000 if fragment else 0, 64, 1, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes(12) + b'\x08\x00' + ip + icmp


def ping(namespace, source, destination, count, fragment=False):
    args = ['ip', 'netns', 'exec', namespace, 'ping', '-n', '-c', str(count), '-W', '1']
    if fragment:
        args += ['-s', '3000']
    args += ['-I', source, destination]
    result = run(args, timeout=count + 5)
    summaries = re.findall(r'^(\d+) packets transmitted, (\d+) (?:packets )?received,([^\n]*)', result.stdout, re.M)
    if result.returncode not in [0, 1] or len(summaries) != 1:
        raise Unverified('ping failed or lacks one recognizable summary')
    sent, received = map(int, summaries[0][:2])
    if re.search(r'\berrors?\b', summaries[0][2]):
        raise Unverified('ping reported network errors')
    if sent != count or not 0 <= received <= sent or (result.returncode == 0) != (received > 0):
        raise Unverified('inconsistent ping result')
    return received


def verify(interface, namespace, source, destination, control, count, fragment):
    if source == control:
        raise Unverified('control must be a separate source')
    if ping(namespace, control, destination, 1) != 1:
        raise Unverified('control path is unavailable')
    before = attachment(interface)
    with tempfile.TemporaryDirectory(prefix='sokol-xdp-frame-') as directory:
        packet = Path(directory) / 'icmp.bin'
        packet.write_bytes(frame(source, destination, fragment))
        result = read_json(['bpftool', '-j', 'prog', 'run', 'id', str(before[0]),
                            'data_in', str(packet), 'repeat', '1'])
    if not isinstance(result, dict) or type(result.get('retval')) is not int:
        raise Unverified('missing or invalid kernel verdict')
    verdict = result['retval']
    if verdict not in [1, 2]:  # Linux XDP_DROP, XDP_PASS; abort/redirect/TX are not our verdicts.
        raise Unverified('unexpected kernel verdict')
    if verdict == 2:
        return 1
    received = ping(namespace, source, destination, count, fragment)
    if ping(namespace, control, destination, 1) != 1:
        raise Unverified('control path was lost')
    if attachment(interface) != before:
        raise Unverified('XDP attachment changed during the probe')
    if received != 0:
        return 1
    print(f'      XDP proof: id {before[0]}, {source}, {"fragment" if fragment else "plain"}, kernel DROP, {count} sent/0 received, controls pass')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['interface', 'namespace', 'source', 'destination', 'control']:
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--count', type=int, choices=[1, 2], required=True)
    parser.add_argument('--fragment', action='store_true')
    args = parser.parse_args()
    try:
        return verify(args.interface, args.namespace, args.source, args.destination,
                      args.control, args.count, args.fragment)
    except (Unverified, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print('UNVERIFIED XDP probe: ' + str(error))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
