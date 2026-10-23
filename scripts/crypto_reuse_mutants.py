#!/usr/bin/env python3
"""External qualification driver, not transport/product code. Serial only."""
import hashlib,json,os,pathlib,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1]
out=pathlib.Path(sys.argv[1]).resolve(); out.mkdir(parents=True,exist_ok=True)
crypto=root/'crates/beacon-core/src/crypto.rs'; transport=root/'crates/oh-core/src/transport.rs'
original={p:p.read_text() for p in [crypto,transport]}
checks=[
('replay-clear',crypto,'return Err(BeaconError::ReplayCapacityExceeded(self.max_capacity));','self.seen.clear();','beacon-core','crypto::hardening_tests::replay_capacity_retains_history','capacity must refuse'),
('encrypt-unchecked',crypto,'    if !shared_secret.was_contributory() {\n        return Err(BeaconError::KeyAgreementFailed);\n    }\n','', 'beacon-core','crypto::hardening_tests::peer_encrypt_refuses_noncontributory','encrypt must reject'),
('decrypt-unchecked',crypto,'    if !shared_secret.was_contributory() {\n        return Err(BeaconError::KeyAgreementFailed);\n    }\n','', 'beacon-core','crypto::hardening_tests::peer_decrypt_refuses_predictable_zero_key_forgery','decrypt must reject'),
('send-wrap',transport,'        if self.send_counter == u64::MAX {','        if false {','oh-core','transport::lifecycle_tests::counters_stop_before_wrap_without_io','send exhaustion must refuse'),
('recv-exhaustion',transport,'        if self.recv_counter == u64::MAX {\n            return Err(io::Error::other("record counter exhausted"));\n        }\n','', 'oh-core','transport::lifecycle_tests::counters_stop_before_wrap_without_io','exhaustion must be refused'),
('session-unbound',transport,'    material.extend_from_slice(transcript.finalize().as_bytes());','    let _ = transcript.finalize();','oh-core','transport::lifecycle_tests::transcript_binding_with_persistent_identity_and_fixed_shared_secret','fresh transcript must bind'),
('read-resume',transport,'                    self.broken = true;\n                    return Err(e);','                    return Err(e);','oh-core','transport::lifecycle_tests::terminal_partial_reads_and_eof','terminal read must refuse'),
('write-resume',transport,'                self.broken = true;\n                return Err(e);','                return Err(e);','oh-core','transport::lifecycle_tests::terminal_io_errors_at_record_boundaries','terminal read must refuse'),
]
results=[]
def command(args,name):
 try:
  r=subprocess.run(args,cwd=root,capture_output=True,text=True,timeout=180)
  (out/(name+'.log')).write_text(r.stdout+r.stderr)
  return r
 except subprocess.TimeoutExpired as e:
  (out/(name+'.log')).write_text(str(e));return None
try:
 for name,p,old,new,package,test,assertion in checks:
  text=original[p]
  if name=='decrypt-unchecked':
   pos=text.index('pub fn decrypt_from_peer');text=text[:pos]+text[pos:].replace(old,new,1)
  else:
   if old not in text:raise RuntimeError('mutation not matched: '+name)
   text=text.replace(old,new,1)
  if name=='send-wrap':
   text=text.replace('self.send_counter += 1;', 'self.send_counter = self.send_counter.wrapping_add(1);',1)
  p.write_text(text)
  build=command(['cargo','test','--locked','-p',package,'--lib','--no-run','--message-format=json'],name+'-build')
  status='INVALID'; observed='compile/timeout failure';rc=None
  if build is not None and build.returncode==0:
   artifacts=[json.loads(l) for l in build.stdout.splitlines() if l.startswith('{')]
   bins=[a['executable'] for a in artifacts if a.get('reason')=='compiler-artifact' and a.get('executable') and a.get('profile',{}).get('test')]
   if len(bins)!=1:raise RuntimeError('ambiguous test binary')
   binary=bins[0]; digest=hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()
   r=command([binary,'--exact',test,'--nocapture'],name+'-run')
   if r is not None:
    rc=r.returncode;log=r.stdout+r.stderr
    expected_path='crypto_hardening_tests.rs' if package=='beacon-core' else 'transport_lifecycle_tests.rs'
    if rc==101 and 'running 1 test' in log and '1 failed' in log and assertion in log and expected_path in log:
     status='PASS';observed='intended assertion rejected compiled mutant'
    elif rc==0:status='FAIL';observed='mutant survived'
    else:observed='not intended assertion'
  results.append({'mutant':name,'status':status,'test':test,'expected_assertion':assertion,'observed':observed,'exit':rc,'binary_sha256':digest if build is not None and build.returncode==0 else None})
  p.write_text(original[p])
  print(json.dumps(results[-1]),flush=True)
finally:
 for p,text in original.items():p.write_text(text)
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
if len(results)!=len(checks) or any(r['status']!='PASS' for r in results):sys.exit(1)
