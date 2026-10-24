"""Defensive fixtures only. Network tests are opt-in, bounded, nondestructive."""
import copy,datetime,importlib.util,json,pathlib,runpy,socket,subprocess,threading,types,unittest
from unittest.mock import patch
D=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('boundary',D/'dk02_transport.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
template=json.loads((D/'genuine-controller-readiness.json').read_text())['nativeProbe']
c=runpy.run_path(str(D/'continuation.PROPOSED.py'))['main'].__globals__
def result():
    r=copy.deepcopy(template);r['checkedUTC']=datetime.datetime.now(datetime.timezone.utc).isoformat();return r
def transport():
    t=b.Transport.__new__(b.Transport);t.authority=json.loads((D/'transport-authority.PROPOSED.json').read_text());t.last=None;return t

class Boundary(unittest.TestCase):
    def test_low_cpu(self):
        r=result();r['capacity']['cpus']=1
        with self.assertRaisesRegex(ValueError,'Linux capacity'):b.validate(r,r['nonce'])
    def test_unapproved_profile(self):self.rejects('operationProfile','build','status/nonce')
    def test_old_profile_schema(self):self.rejects('schemaVersion',1,'status/nonce')
    def test_nonzero_remote_write_budget(self):
        r=result();r['capacity']['requiredScratchBytes']=1
        with self.assertRaisesRegex(ValueError,'Linux capacity'):b.validate(r,r['nonce'])
    def test_readonly_profile_does_not_require_build_scratch_fixture(self):
        r=result();r['capacity']['workFree']=1024
        self.assertEqual(b.validate(r,r['nonce'])['operationProfile'],'settlement-read-only-v1')

    def rejects(self,field,value,message):
        r=result();r[field]=value
        with self.assertRaisesRegex((ValueError,KeyError,TypeError),message):b.validate(r,r['nonce'])
    def test_real_record_valid_at_original_time(self):
        self.assertIs(b.validate(template,template['nonce'],datetime.datetime.fromisoformat(template['checkedUTC'])),template)
    def test_wrong_host(self):self.rejects('hostname','other','Unapproved Linux host')
    def test_wrong_machine(self):self.rejects('machineID','0'*32,'Unapproved Linux host')
    def test_wrong_daemon(self):self.rejects('daemonID','other','Unapproved Linux host')
    def test_wrong_endpoint(self):self.rejects('endpoint','tcp://other:2375','Unapproved Linux host')
    def test_wrong_account(self):self.rejects('account','root','Unapproved Linux account')
    def test_wrong_nonce(self):
        r=result()
        with self.assertRaisesRegex(ValueError,'status/nonce'):b.validate(r,'0'*32)
    def test_stale(self):self.rejects('checkedUTC','2020-01-01T00:00:00Z','Stale Linux check')
    def test_wrong_workflow(self):self.rejects('workflowSHA256','0'*64,'authority/scope')
    def test_mutation_scope(self):self.rejects('DockerMutations',1,'authority/scope')
    def test_low_capacity(self):
        r=result();r['capacity']['availableMemory']=2*1024**3-1
        with self.assertRaisesRegex(ValueError,'Linux capacity'):b.validate(r,r['nonce'])
    def test_wrong_image(self):
        r=result();r['images'][0]['Id']='sha256:'+'0'*64
        with self.assertRaisesRegex(ValueError,'Linux image identity'):b.validate(r,r['nonce'])
    def test_wrong_source(self):
        r=result();r['images'][0]['sourceManifestSHA256']='0'*64
        with self.assertRaisesRegex(ValueError,'Linux image identity'):b.validate(r,r['nonce'])
    def test_missing_fields(self):
        r=result();del r['commands']
        with self.assertRaisesRegex(ValueError,'Malformed Linux check'):b.validate(r,r['nonce'])
    def test_command_failure(self):
        r=result();r['commands'][0]['exitCode']=1
        with self.assertRaisesRegex(ValueError,'command failure/scope'):b.validate(r,r['nonce'])
    def test_command_substitution(self):
        r=result();r['commands'][0]['arguments']=['docker','rm','other']
        with self.assertRaisesRegex(ValueError,'command failure/scope'):b.validate(r,r['nonce'])
    def test_malformed_json(self):
        with self.assertRaises(json.JSONDecodeError):b.parse('{')
    def test_duplicate_json(self):
        with self.assertRaisesRegex(ValueError,'Duplicate'):b.parse('{"a":1,"a":2}')
    def test_nonfinite_json(self):
        with self.assertRaisesRegex(ValueError,'Nonfinite'):b.parse('{"a":NaN}')
    def test_mutation_rejected_before_probe(self):
        t=transport()
        with patch.object(t,'probe',side_effect=AssertionError('must not dispatch')) as probe:
            with self.assertRaisesRegex(ValueError,'Unapproved remote Docker operation'):t.execute_readonly(b.D+['rm','other'])
            probe.assert_not_called()
    def test_unapproved_image_rejected_before_probe(self):
        t=transport()
        with patch.object(t,'probe') as probe:
            with self.assertRaisesRegex(ValueError,'Unapproved remote Docker operation'):t.execute_readonly(b.D+['image','inspect','sha256:'+'0'*64])
            probe.assert_not_called()
    def test_execution_options_rejected(self):
        with self.assertRaisesRegex(ValueError,'execution options'):transport().execute_readonly(b.D+['image','inspect',b.IMAGES[0]],env={})
    def test_hash_enforcement(self):
        with self.assertRaisesRegex(ValueError,'identity mismatch'):b.authenticated(D/'dk02_transport.py','0'*64)
    def test_nonzero_preserves_diagnostic(self):
        t=transport()
        with patch.object(b,'authenticated',return_value=b''),patch.object(b.subprocess,'run',return_value=types.SimpleNamespace(returncode=255,stderr='Permission denied',stdout='{}')):
            with self.assertRaisesRegex(ValueError,'exit 255') as e:t.probe()
        self.assertEqual(e.exception.exit_code,255);self.assertEqual(e.exception.diagnostic,'Permission denied')
    def test_timeout_propagates(self):
        with patch.object(b,'authenticated',return_value=b''),patch.object(b.subprocess,'run',side_effect=subprocess.TimeoutExpired('ssh',65)):
            with self.assertRaisesRegex(TimeoutError,'SSH probe timeout'):transport().probe()
    def test_actual_controller_wrong_host_fails(self):
        t=transport();r=result();r['hostname']='other'
        with patch.object(t,'probe',side_effect=lambda:b.validate(r,r['nonce'])):
            w=types.SimpleNamespace(host=t.host,execute=t.execute_readonly,DOCKER=b.D)
            with self.assertRaisesRegex(ValueError,'Unapproved Linux host'):c['live'](w)
    def test_actual_controller_wrong_image_fails(self):
        w=types.SimpleNamespace(host=lambda:None,execute=lambda args:json.dumps([{'Id':'sha256:'+'0'*64}]),DOCKER=b.D)
        with self.assertRaisesRegex(Exception,'Missing or mismatched retained image'):c['live'](w)
    def test_actual_controller_failure_blocks_image_lookup(self):
        w=types.SimpleNamespace(host=lambda:(_ for _ in ()).throw(ValueError('Insufficient capacity')),execute=unittest.mock.Mock(),DOCKER=b.D)
        with self.assertRaisesRegex(ValueError,'Insufficient capacity'):c['live'](w)
        w.execute.assert_not_called()

def real_network_controls():
    """No success simulation; deny all auth on approved server; own loopback listeners."""
    a=json.loads((D/'transport-authority.PROPOSED.json').read_text());exe=a['ssh']['path']
    for k in ('ssh','config','knownHosts'):b.authenticated(a[k]['path'],a[k]['sha256'])
    args=a['arguments'][:-1]+['-o','PubkeyAuthentication=no','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
      '-o','GSSAPIAuthentication=no','-o','HostbasedAuthentication=no',a['arguments'][-1],'hostname']
    outcomes=[]
    r=subprocess.run([exe,*args],capture_output=True,text=True,timeout=20)
    assert r.returncode==255 and 'Permission denied' in r.stderr
    outcomes.append({'case':'authentication-failure','exitCode':r.returncode,'diagnostic':r.stderr})
    # Reserved owned socket is bound but not listening: never contact another service.
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1]
        base=[exe,'-F','NUL','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=1','-p',str(port),'user@127.0.0.1','hostname']
        r=subprocess.run(base,capture_output=True,text=True,timeout=5)
    with (D/'loopback-refused-observation.json').open('w') as f:json.dump({'exitCode':r.returncode,'diagnostic':r.stderr},f,indent=2)
    assert r.returncode==255 and ('refused' in r.stderr.lower() or 'connection timed out' in r.stderr.lower())
    outcomes.append({'case':'transport-unavailable-owned-port','exitCode':r.returncode,'diagnostic':r.stderr})
    settled=threading.Event();accepted=threading.Event()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(4)
        def stall():
            try:
                conn,_=listener.accept();accepted.set()
                with conn:settled.wait(3)
            finally:settled.set()
        worker=threading.Thread(target=stall);worker.start()
        try:
            base[base.index('-p')+1]=str(listener.getsockname()[1])
            r=subprocess.run(base,capture_output=True,text=True,timeout=5)
        finally:settled.set();worker.join(5)
    assert accepted.is_set() and not worker.is_alive() and r.returncode==255 and 'timed out' in r.stderr.lower()
    outcomes.append({'case':'transport-timeout','exitCode':r.returncode,'diagnostic':r.stderr,'ownedWorkerSettled':True})
    with (D/'real-transport-negative-controls.json').open('x') as f:json.dump({'status':'PASS','cases':outcomes},f,indent=2)
    print('PASS: three real nondestructive SSH negative controls; owned listener settled')

if __name__=='__main__':
    import sys
    if sys.argv[1:]==['--real-network-controls']:real_network_controls()
    else:unittest.main(verbosity=2)
