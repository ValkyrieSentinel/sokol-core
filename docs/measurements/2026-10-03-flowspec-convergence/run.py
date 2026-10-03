from pathlib import Path
import subprocess,json,time,tempfile,socket,sys
root=Path(sys.argv[1]);inject=sys.argv[2];output=Path(sys.argv[3])
with tempfile.TemporaryDirectory(prefix='sokol-gobgp-id-') as temp:
 p=Path(temp)
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
 cfg=p/'gobgp.toml';cfg.write_text('[global.config]\nas = 65001\nrouter-id = "127.0.0.1"\nport = -1\n')
 with (p/'daemon.log').open('w') as log:
  daemon=subprocess.Popen([str(root/'gobgpd'),'-f',str(cfg),'--api-hosts',f'127.0.0.1:{port}'],stdout=log,stderr=log)
  try:
   for _ in range(50):
    ready=subprocess.run([str(root/'gobgp'),'-p',str(port),'global'],capture_output=True,timeout=5)
    if ready.returncode==0:break
    time.sleep(.1)
   else:raise RuntimeError('GoBGP did not start')
   subprocess.run([inject,f'127.0.0.1:{port}','inject'],check=True,timeout=15)
   ids_before=subprocess.check_output([inject,f'127.0.0.1:{port}','read'],timeout=15,text=True)
   entries=[]
   for family,prefix in [('ipv4-flowspec','198.51.100.7/32'),('ipv6-flowspec','2001:db8::7/128')]:
    cmd=[str(root/'gobgp'),'-p',str(port),'global','rib','-a',family]
    before=subprocess.run(cmd+['-j'],capture_output=True,timeout=5);assert before.returncode==0
    delete=subprocess.run(cmd+['del','match','source',prefix,'then','discard','community','65001:6666'],capture_output=True,timeout=5)
    after=subprocess.run(cmd+['-j'],capture_output=True,timeout=5);assert after.returncode==0
    entries.append({'family':family,'prefix':prefix,'before':before.stdout.decode(),'delete_exit':delete.returncode,'delete_stderr':delete.stderr.decode(),'after':after.stdout.decode()})
   ids_after=subprocess.check_output([inject,f'127.0.0.1:{port}','read'],timeout=15,text=True)
   assert all(json.loads(line)['identifier'] == 7 for line in ids_before.splitlines())
   assert ids_before == ids_after and len(ids_before.splitlines()) == 2
   for case in entries:
    assert case['delete_exit'] == 0 and case['before'] == case['after']
    paths=[path for paths in json.loads(case['before']).values() for path in paths]
    assert len(paths) == 1 and paths[0]['LocalID'] == 0
   report={'api_identifiers_before':ids_before,'api_identifiers_after':ids_after,'cases':entries}
   output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
  finally:
   daemon.terminate()
   try:daemon.wait(timeout=5)
   except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
