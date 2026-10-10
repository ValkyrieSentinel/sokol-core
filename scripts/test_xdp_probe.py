"""Actual drop assertions must require a kernel verdict and valid live probe."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
# Captured from the original call sites before implementing the helper.
EXPECTATIONS = {'traffic from blocked $BLOCKED_IP is dropped': ['BLOCKED_IP', 2, 'plain'],
 'a banned address is dropped before it moves to this node': ['MOVED_IP', 2, 'plain'],
 'an address inside the banned prefix is dropped in XDP': ['CIDR_IP', 2, 'plain'],
 'operator ban is enforced in XDP': ['ALLOWED_IP', 1, 'plain'],
 'Suricata alert blocks the probing address in XDP': ['PROBE_IP', 2, 'plain'],
 'CrowdSec ban blocks the address in XDP': ['CS_IP', 2, 'plain'],
 'a decision made while the node was down is enforced once it is back': ['CS_IP2', 2, 'plain'],
 'trident trap blocks a silent connection in XDP': ['TRAP_IP', 2, 'plain'],
 'root IPC DROP_IMMEDIATE blocks $ALLOWED_IP': ['ALLOWED_IP', 2, 'plain'],
 'an operator ban survives a restart': ['PERSIST_IP', 2, 'plain'],
 'an operator ban answered OK survives SIGKILL right after the answer': ['KILL_BAN',
                                                                         2,
                                                                         'plain'],
 'the ban is enforced although not yet durable': ['HUNG_IP', 2, 'plain'],
 'strict mode: fragmented IPv4 is dropped': ['ALLOWED_IP', 2, 'fragment'],
 'native mode: blocked source is dropped': ['BLOCKED_IP', 1, 'plain'],
 'TTL: dynamic block of $ALLOWED_IP is enforced': ['ALLOWED_IP', 1, 'plain'],
 'TTL: static --block stays in force': ['BLOCKED_IP', 1, 'plain']}
NET = json.dumps([{'xdp': [{'devname': 'probe0', 'ifindex': 7, 'id': 51, 'mode': 'driver'}], 'tc': []}])
FAKE = r'''#!/usr/bin/env python3
import ipaddress,json,os,struct,sys,time
from pathlib import Path
args=sys.argv[1:]
path=Path(os.environ['PROBE_CALLS'])
prior=[json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []
def record(value):
    with path.open('a') as file: file.write(json.dumps(value)+'\n')
if Path(sys.argv[0]).name=='ip':
    assert args[:5]==['netns','exec','probe-ns','ping','-n'],args
    assert args[-1]=='10.231.0.1' and args[-3]=='-I',args
    source=args[-2];control=source=='10.231.0.250'
    count=int(args[args.index('-c')+1]);kind='control' if control else 'target'
    record({'kind':kind,'source':source,'count':count,'fragment':'-s' in args})
    if control:
        after=any(p['kind']=='control' for p in prior)
        status=int(os.environ.get('POST_CONTROL_STATUS' if after else 'CONTROL_STATUS','0'))
        rx=1 if status==0 else 0;sent=count
    else:
        status=int(os.environ.get('IP_STATUS','1'))
        rx=int(os.environ.get('TARGET_RX','0'));sent=int(os.environ.get('TARGET_SENT',str(count)))
    text=f'{sent} packets transmitted, {rx} received, 100% packet loss, time 1000ms\n'
    sys.stdout.write(os.environ.get('TARGET_OUTPUT',text) if not control else text)
    sys.exit(status)
assert args[0]=='-j',args
if args[1:]==['net','show','dev','probe0']:
    after=any(p['kind']=='net' for p in prior);record({'kind':'net'})
    sys.stdout.write(os.environ['NET_AFTER' if after else 'NET_BEFORE'])
    sys.exit(int(os.environ.get('AFTER_STATUS' if after else 'NET_STATUS','0')))
assert args[1:6]==['prog','run','id','51','data_in'] and args[7:]==['repeat','1'],args
packet=Path(args[6]).read_bytes()
assert len(packet)==98 and packet[12:14]==b'\x08\x00' and packet[14]==0x45,packet
assert struct.unpack('!H',packet[16:18])[0]==84 and packet[23]==1 and packet[34:36]==b'\x08\x00',packet
for part in [packet[14:34],packet[34:]]:
    total=sum(int.from_bytes(part[i:i+2],'big') for i in range(0,len(part),2))
    while total>>16:total=(total&65535)+(total>>16)
    assert total==65535,total
source=str(ipaddress.IPv4Address(packet[26:30]));destination=str(ipaddress.IPv4Address(packet[30:34]))
assert destination=='10.231.0.1'
record({'kind':'run','source':source,'fragment':bool(int.from_bytes(packet[20:22],'big')&0x2000)})
time.sleep(float(os.environ.get('RUN_SLEEP','0')))
sys.stdout.write(os.environ['RUN_OUTPUT']);sys.exit(int(os.environ.get('RUN_STATUS','0')))
'''


def commands():
    text = (ROOT / 'scripts/xdp-smoke.sh').read_text().replace('\\\n', ' ')
    matches = [(n, c) for n, c in re.findall(r'^\s*check "([^"\n]+)"\s+([^\n]+)$', text, re.M) if n in EXPECTATIONS]
    if len(matches) != 16 or {n for n, _ in matches} != set(EXPECTATIONS):
        raise AssertionError('missing or duplicate XDP drop assertion')
    return matches


class XdpSmoke(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(prefix='sokol-xdp-probe-')
        self.addCleanup(d.cleanup)
        self.root = Path(d.name)
        for name, target in [('bash', '/bin/bash'), ('python3', sys.executable)]:
            (self.root / name).symlink_to(target)
        fake = self.root / 'fake'
        fake.write_text(FAKE)
        fake.chmod(0o755)
        (self.root / 'ip').symlink_to(fake)
        (self.root / 'bpftool').symlink_to(fake)

    def run_command(self, cmd, **changes):
        values = {name: '10.231.0.'+str(i+2) for i, name in enumerate(sorted({v[0] for v in EXPECTATIONS.values()}))}
        setup = 'NS=probe-ns; HOST_IF=probe0; HOST_IP=10.231.0.1; PROBE_CONTROL_IP=10.231.0.250\n'
        setup += '\n'.join(k+'='+v for k,v in values.items())+'\nXDP_PROBE="$PROBE_SCRIPT"\n'
        smoke = (ROOT / 'scripts/xdp-smoke.sh').read_text()
        function = re.search(r'^xdp_drop\(\) \{.*?^\}', smoke, re.M|re.S)
        if function:
            setup += function.group()+'\n'
        self.calls = self.root / 'calls.jsonl'
        self.calls.unlink(missing_ok=True)
        return subprocess.run(['bash','-euo','pipefail','-c',setup+cmd],
            env={**os.environ,'PATH':str(self.root),'IP_STATUS':'1','PROBE_CALLS':str(self.calls),
                 'PROBE_SCRIPT':str(ROOT/'scripts/xdp_probe.py'), 'NET_BEFORE':NET, 'NET_AFTER':NET,
                 'RUN_OUTPUT':'{"retval":1,"duration":50}', **changes},
            capture_output=True,text=True,timeout=15)

    def test_ping_operational_errors_cannot_prove_a_drop_at_any_actual_call_site(self):
        for name,cmd in commands():
            with self.subTest(name=name):
                result=self.run_command(cmd,IP_STATUS='2')
                self.assertEqual(result.returncode,2,result.stderr+result.stdout)

    def test_no_reply_without_a_kernel_verdict_is_not_proof_at_any_actual_call_site(self):
        (self.root / 'bpftool').unlink()
        for name,cmd in commands():
            with self.subTest(name=name):
                result=self.run_command(cmd)
                self.assertEqual(result.returncode,2,result.stderr+result.stdout)

    def test_all_actual_call_sites_require_kernel_and_live_probe_agreement(self):
        values = {name: '10.231.0.'+str(i+2) for i, name in enumerate(sorted({v[0] for v in EXPECTATIONS.values()}))}
        for name, cmd in commands():
            with self.subTest(name=name):
                result = self.run_command(cmd)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
                self.assertEqual([c['kind'] for c in calls], ['control', 'net', 'run', 'target', 'control', 'net'])
                source, count, kind = EXPECTATIONS[name]
                self.assertEqual(calls[2]['source'], values[source])
                self.assertEqual(calls[2]['fragment'], kind == 'fragment')
                self.assertEqual(calls[3]['source'], values[source])
                self.assertEqual(calls[3]['count'], count)
                self.assertEqual(calls[3]['fragment'], kind == 'fragment')

    def test_live_replies_and_kernel_pass_are_contradictions_at_every_call_site(self):
        for name, cmd in commands():
            for changes in [{'RUN_OUTPUT':'{"retval":2}'}, {'IP_STATUS':'0', 'TARGET_RX':'1'}]:
                with self.subTest(name=name, changes=changes):
                    result = self.run_command(cmd, **changes)
                    self.assertEqual(result.returncode, 1, result.stderr + result.stdout)

    def test_unverified_adapter_results_fail_the_actual_smoke_wrapper(self):
        entry = {'devname':'probe0','ifindex':7,'id':51,'mode':'driver'}
        scenarios = [
            {'NET_STATUS':'7'}, {'RUN_STATUS':'7'}, {'AFTER_STATUS':'7'},
            {'RUN_OUTPUT':'{"retval":true}'}, {'RUN_OUTPUT':'{"retval":1.0}'},
            {'RUN_OUTPUT':'{"retval":1,"retval":1}'}, {'RUN_OUTPUT':'{}'},
            {'RUN_OUTPUT':'{"retval":0}'}, {'RUN_OUTPUT':'{"retval":3}'},
            {'RUN_OUTPUT':'{"retval":4}'}, {'RUN_OUTPUT':'not JSON'},
            {'NET_BEFORE':'[]'}, {'NET_BEFORE':'[{"xdp":[]}]'},
            {'NET_BEFORE':json.dumps([{'xdp':[dict(entry,devname='wrong')]}])},
            {'NET_BEFORE':json.dumps([{'xdp':[entry,entry]}])},
            {'NET_BEFORE':json.dumps([{'xdp':[dict(entry,id=True)]}])},
            {'NET_BEFORE':json.dumps([{'xdp':[dict(entry,mode='offload')]}])},
            {'NET_AFTER':json.dumps([{'xdp':[dict(entry,id=52)]}])},
            {'NET_AFTER':json.dumps([{'xdp':[dict(entry,ifindex=8)]}])},
            {'NET_AFTER':json.dumps([{'xdp':[dict(entry,mode='generic')]}])},
            {'CONTROL_STATUS':'1'}, {'POST_CONTROL_STATUS':'1'},
            {'TARGET_OUTPUT':''}, {'TARGET_RX':'1'}, {'TARGET_SENT':'0'},
            {'TARGET_OUTPUT':'2 packets transmitted, 0 received, +1 errors, 100% packet loss, time 1000ms\n'},
        ]
        _, cmd = commands()[0]
        source = (ROOT/'scripts/xdp-smoke.sh').read_text()
        wrapper = re.search(r'^check\(\) \{.*?^\}', source, re.M|re.S).group()
        for changes in scenarios:
            with self.subTest(changes=changes):
                result = self.run_command(cmd, **changes)
                self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
                wrapped = wrapper+'\nFAILED=0\ncheck probe '+cmd+'\nexit "$FAILED"'
                result = self.run_command(wrapped, **changes)
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn('FAIL  probe', result.stdout)
                self.assertNotIn('PASS', result.stdout)
    def test_missing_ip_and_a_timed_out_kernel_tool_are_unverified(self):
        _, cmd = commands()[0]
        ip = self.root/'ip'
        ip.unlink()
        result = self.run_command(cmd)
        self.assertEqual(result.returncode, 2, result.stderr+result.stdout)
        ip.symlink_to(self.root/'fake')
        result = self.run_command(cmd, RUN_SLEEP='6')
        self.assertEqual(result.returncode, 2, result.stderr+result.stdout)
        self.assertIn('timed out', result.stdout)


if __name__ == '__main__':
    unittest.main()
