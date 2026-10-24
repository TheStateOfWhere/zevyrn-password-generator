"""Fixed unprivileged DK02 probe. No mutations, arbitrary commands or environment dump."""
import datetime,hashlib,json,os,pathlib,re,shutil,signal,socket,stat,subprocess,sys,time,types

def main():
    import pwd

    def require(ok,message):
        if not ok:raise ValueError(message)
    request=json.load(sys.stdin)
    require(set(request)=={'nonce','bindings','workflowSHA256'} and re.fullmatch('[0-9a-f]{32}',request['nonce']), 'Invalid probe request')
    b=request['bindings']
    require(re.fullmatch('[0-9a-f]{64}',request['workflowSHA256']) and re.fullmatch('[0-9a-f]{32}',b['machineID']) and re.fullmatch('[a-z0-9.-]+',b['hostname']),'Probe identity')
    require(sys.platform=='linux' and os.getuid()==1000,'Approved Linux account required')
    require(pwd.getpwuid(os.getuid()).pw_name=='user','Approved account name required')
    signal.signal(signal.SIGHUP,signal.SIG_IGN) # finish bounded read-only batch if SSH drops
    deadline=time.monotonic()+50
    digest=request['workflowSHA256'];w=types.SimpleNamespace(MACHINE=b['machineID'],DAEMON=b['daemonID'])
    D=['docker','--host','unix:///var/run/docker.sock']
    images=[b['images'][k] for k in ('builder','runtime')]
    require(all(re.fullmatch('sha256:[0-9a-f]{64}',v) for v in images),'Probe image identities')
    allowed=[['hostname'],D+['info','--format','{{.ID}}'],D+['info','--format','{{.DockerRootDir}}'],
     D+['context','inspect','default','--format','{{.Endpoints.docker.Host}}'],
     D+['image','inspect',*images],D+['ps','-aq','--no-trunc','--filter','name=^/keysmith-keysmith-1$'],
     D+['network','inspect','proxy','bridge','none']]
    commands=[];owned_id=None
    def checked(args):
        require(args in allowed or (owned_id is not None and args==D+['inspect',owned_id]),'Unapproved read-only command')
        remaining=deadline-time.monotonic()
        require(remaining>0,'Read-only batch deadline')
        r=subprocess.run(args,capture_output=True,text=True,timeout=min(15,remaining))
        commands.append({'arguments':args,'exitCode':r.returncode})
        require(r.returncode==0,'Read-only command failed: '+str(args[:4]))
        return r.stdout.strip()
    require(checked(['hostname'])==b['hostname'] and pathlib.Path('/etc/machine-id').read_text().strip()==b['machineID'],'Hostname/machine mismatch')
    require(checked(D+['info','--format','{{.ID}}'])==b['daemonID'],'Docker daemon mismatch')
    require(checked(D+['context','inspect','default','--format','{{.Endpoints.docker.Host}}'])=='unix:///var/run/docker.sock','Docker endpoint mismatch')
    require(not any(v for k,v in os.environ.items() if k.startswith(('DOCKER_','BUILDX_','BUILDKIT_')) and k!='DOCKER_HOST'),'Unexpected endpoint environment')
    require(os.environ.get('DOCKER_HOST','unix:///var/run/docker.sock')=='unix:///var/run/docker.sock','Endpoint environment')
    require(socket.gethostname()==b['hostname'],'Hostname mismatch')
    rows=json.loads(checked(D+['image','inspect',*images]))
    require(len(rows)==2 and {r['Id'] for r in rows}==set(images),'Retained image mismatch')
    proof=[]
    for r in rows:
        labels=r['Config'].get('Labels') or {}
        require(labels.get('io.zevyrn.source-manifest-sha256')==b['sourceManifestSHA256'],'Image source mismatch')
        if r['Id']==images[1]:require(labels.get('io.zevyrn.builder-image-id')==images[0],'Builder relationship mismatch')
        proof.append({'Id':r['Id'],'sourceManifestSHA256':labels['io.zevyrn.source-manifest-sha256'],
                      'builderImageID':labels.get('io.zevyrn.builder-image-id')})
    ids=checked(D+['ps','-aq','--no-trunc','--filter','name=^/keysmith-keysmith-1$']).split()
    require(len(ids)==1 and re.fullmatch('[0-9a-f]{64}',ids[0]),'KeySmith identity missing/ambiguous')
    owned_id=ids[0]
    app=json.loads(checked(D+['inspect',owned_id]))
    require(len(app)==1 and app[0]['Name']=='/keysmith-keysmith-1','KeySmith selection mismatch')
    c=app[0]
    health=c['State'].get('Health',{}).get('Status')
    require(c['State']['Status']=='running' and health=='healthy','KeySmith unhealthy')
    networks=json.loads(checked(D+['network','inspect','proxy','bridge','none']))
    require(len(networks)==3 and {n['Name'] for n in networks}=={'proxy','bridge','none'},'Required networks missing')
    docker_root=checked(D+['info','--format','{{.DockerRootDir}}'])
    memory=dict(line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    capacity={'cpus':os.cpu_count(),'availableMemory':int(memory['MemAvailable'].split()[0])*1024,
              'workFree':shutil.disk_usage('/tmp').free,'dockerFree':shutil.disk_usage(docker_root).free}
    require(capacity['cpus']>=2 and capacity['availableMemory']>=2*1024**3 and
            min(capacity['workFree'],capacity['dockerFree'])>=0,'Insufficient capacity')
    # This authenticated profile has no remote temporary-file or Docker-write operation.
    capacity['requiredScratchBytes']=0
    interpreter=pathlib.Path(sys.executable).resolve();info=interpreter.stat()
    require(info.st_uid==0 and not info.st_mode&0o022,'Unprotected Linux interpreter')
    print(json.dumps({'schemaVersion':2,'operationProfile':'settlement-read-only-v1','status':'PASS','nonce':request['nonce'],
     'checkedUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'hostname':socket.gethostname(),
     'account':'user','uid':os.getuid(),'platform':sys.platform,'machineID':w.MACHINE,'daemonID':w.DAEMON,
     'endpoint':'unix:///var/run/docker.sock','workflowSHA256':digest,'readOnly':True,'DockerMutations':0,
     'images':proof,'capacity':capacity,'application':{'Id':c['Id'],'image':c['Image'],'name':c['Name'],
     'started':c['State']['StartedAt'],'status':c['State']['Status'],'health':health,
     'networks':sorted(c['NetworkSettings']['Networks'])},
     'networks':[{'Id':n['Id'],'Name':n['Name']} for n in networks],
     'interpreter':{'path':str(interpreter),'sha256':hashlib.sha256(interpreter.read_bytes()).hexdigest()},
     'commands':commands}))

if __name__=='__main__':main()
