"""Actual inline JS starts without any external script or functioning canvas."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OfflineOperator(unittest.TestCase):
    def test_no_remote_assets_and_state_readback_survives_a_missing_canvas(self):
        source = (ROOT / 'orchestrator/src/bin/sokol-operator.rs').read_text()
        html = source.split('const HTML_DASHBOARD: &str = r###"', 1)[1].split('"###;', 1)[0]
        self.assertNotRegex(html, r'<script[^>]+src=|<link[^>]+href="https?://')
        script = re.search(r'<script>(.*?)</script>', html, re.S).group(1)
        node = shutil.which('node')
        if not node:
            self.fail('Node is required for the operator startup regression (no silent skip)')
        harness = r'''
const vm = require('node:vm'), fs = require('node:fs'), assert = require('node:assert/strict');
const elements = new Map(), streams = [];
let polls = 0, reads = 0, listeners = 0;
const element = id => {
  if (!elements.has(id)) elements.set(id, {classList:{add(){},remove(){}}, getContext(){throw Error('canvas unavailable')}, textContent:'', innerText:'', value:''});
  return elements.get(id);
};
const data = {timestamp:0, nodes:[], alerts:[], metrics:{p2p_active_peers:0,dag_tips:0,db_latency_ms:0,
 traps:{tier1_bot_tarpit:0,tier1_5_slow_drip:0,tier2_payload_capture:0,tier3_interactive_jail:0,active_banned_ips:0}}};
const world = {document:{getElementById:element,addEventListener(){listeners++},querySelectorAll(){return []},activeElement:null},
 window:{}, setInterval(){polls++}, fetch:async()=>{reads++;return {status:200,ok:true,json:async()=>data}},
 EventSource:class {constructor(){streams.push(this)} close(){}}};
vm.createContext(world);
vm.runInContext(fs.readFileSync(process.argv[2],'utf8'),world);
setImmediate(async()=>{
  assert.equal(polls,1); assert.equal(reads,1); assert.equal(listeners,1); assert.equal(streams.length,1);
  assert.match(element('data-status').textContent,/observations received/);
  streams[0].onmessage({data:JSON.stringify({cpu:12,pps_rx:9,drops_sec:3})});
  assert.equal(element('m-cpu').innerText,'12.0%');
  streams[0].onerror(); assert.equal(element('m-cpu').innerText,'—');
  world.report({outcome:'UNKNOWN'});
  assert.match(element('command-status').textContent,/may have taken effect/);
  world.fetch = async()=>{throw Error('offline')};
  await world.fetchData();
  assert.equal(element('m-peers').innerText,'—');
  assert.equal(element('trap-t1').innerText,'—');
  console.log('PASS offline startup, readback, unavailable canvas, stream loss, UNKNOWN command');
});
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'inline.js').write_text(script)
            (path / 'harness.cjs').write_text(harness)
            result = subprocess.run([node, str(path / 'harness.cjs'), str(path / 'inline.js')], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASS offline startup', result.stdout)


if __name__ == '__main__': unittest.main()
