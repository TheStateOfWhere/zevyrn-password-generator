"""Prepare reviewed bytes and explicit Git-derived mode metadata; never execute remotely."""
import pathlib,json,hashlib,tarfile,io,base64
from runtime_context import active

def prepare():
    ctx=active();ctx.require_phase('native-linux-execution')
    R=pathlib.Path(ctx.profile()['executionRoot'])/'staging';S=R.parent/'source'
    manifest_bytes=(R/'source-manifest.json').read_bytes();policy_bytes=(R/'source-mode-policy.json').read_bytes()
    manifest=json.loads(manifest_bytes);policy=json.loads(policy_bytes)
    sha=lambda b:hashlib.sha256(b).hexdigest()
    assert sha(policy_bytes)==manifest['modePolicySHA256']
    with (R/'source.tar').open('xb') as stream:
        with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            for row in manifest['source']:
                content=(S/row['path']).read_bytes()
                assert len(content)==row['bytes'] and sha(content)==row['sha256']
                assert row['mode']==policy['files'][row['path']]
                member=tarfile.TarInfo(row['path']);member.size=len(content);member.mode=row['mode'];member.mtime=0;member.uid=member.gid=0
                archive.addfile(member,io.BytesIO(content))
    data=(R/'source.tar').read_bytes()
    with (R/'stage-input.json').open('x') as f:json.dump({'policyJSON':policy_bytes.decode(),'manifestJSON':manifest_bytes.decode(),'archiveBase64':base64.b64encode(data).decode()},f)
    footer="\nif __name__=='__main__':\n    print(json.dumps(main(json.load(sys.stdin),%r,%r,%r,%r),indent=2))\n"%('/home/user/zevyrn-builder-staging-candidate-20261023-01',sha(policy_bytes),sha(manifest_bytes),sha(data))
    with (R/'stage-execution.py').open('x') as f:f.write((R/'stage_source.py').read_text()+footer)
    with (R/'stage-authority.json').open('x') as f:json.dump({'workspace':'/home/user/zevyrn-builder-staging-candidate-20261023-01','policySHA256':sha(policy_bytes),'manifestSHA256':sha(manifest_bytes),'archiveSHA256':sha(data),'executionSHA256':sha((R/'stage-execution.py').read_bytes()),'files':len(manifest['source']),'executed':False},f,indent=2)
    print((R/'stage-authority.json').read_text())

if __name__=='__main__':raise SystemExit('BLOCKED: external bootstrap required')
