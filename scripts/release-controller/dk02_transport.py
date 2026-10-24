"""Isolated fixed read-only SSH boundary. No generic remote command interface."""
import base64,datetime as dt,hashlib,json,pathlib,re,secrets,stat,subprocess
from runtime_context import active

def bindings():return active().profile()['bindings']
def identities():return [bindings()['images'][k] for k in ('builder','runtime')]
D=['docker','--host','unix:///var/run/docker.sock']

def require(ok,message):
    if not ok:raise ValueError(message)

def authenticated(path,digest):
    p=pathlib.Path(path).absolute()
    for part in [*reversed(p.parents),p]:
        s=part.lstat()
        require(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'Linked transport identity')
    raw=p.read_bytes();require(hashlib.sha256(raw).hexdigest()==digest,'Transport identity mismatch')
    return raw

def pairs(rows):
    out={}
    for k,v in rows:
        require(k not in out,'Duplicate transport JSON key');out[k]=v
    return out

def parse(raw):return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:require(False,'Nonfinite transport JSON'))

def validate_arguments(authority,profile):
    args=authority.get('arguments')
    require(type(args) is list and len(args)>6 and type(args[4]) is str and pathlib.Path(args[4]).is_absolute(),'SSH identity argument')
    host=profile.get('sshHost')
    require(type(host) is str and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9.-]*',host),'Approved SSH host binding required')
    expected=['-T','-F',authority['config']['path'],'-i',args[4],'-l',profile['account']]
    for option in ('BatchMode=yes','StrictHostKeyChecking=yes','IdentitiesOnly=yes','PreferredAuthentications=publickey',
                   'HostKeyAlgorithms=ssh-ed25519','UpdateHostKeys=no','UserKnownHostsFile='+authority['knownHosts']['path'],
                   'ForwardAgent=no','ClearAllForwardings=yes','ConnectTimeout=12'):
        expected+=['-o',option]
    expected.append(host)
    require(args==expected,'SSH strict argument structure')
    return expected

def validate(result,nonce,now=None):
    now=now or dt.datetime.now(dt.timezone.utc)
    require(isinstance(result,dict) and set(result)=={'schemaVersion','operationProfile','status','nonce','checkedUTC','hostname',
      'account','uid','platform','machineID','daemonID','endpoint','workflowSHA256','readOnly','DockerMutations',
      'images','capacity','application','networks','interpreter','commands'},'Malformed Linux check')
    require(result['schemaVersion']==2 and result['operationProfile']=='settlement-read-only-v1' and result['status']=='PASS' and result['nonce']==nonce,'Linux check status/nonce')
    require(result['hostname']==bindings()['hostname'] and result['machineID']==bindings()['machineID'] and
      result['daemonID']==bindings()['daemonID'] and result['endpoint']=='unix:///var/run/docker.sock',
      'Unapproved Linux host/daemon/endpoint')
    require(result['account']=='user' and result['uid']==1000 and result['platform']=='linux','Unapproved Linux account/platform')
    require(result['workflowSHA256']==active().code_hash('workflow.py') and
      result['readOnly'] is True and result['DockerMutations']==0,'Linux check authority/scope')
    t=dt.datetime.fromisoformat(result['checkedUTC'].replace('Z','+00:00'))
    require(t.tzinfo is not None and -5 <= (now-t).total_seconds() <=180,'Stale Linux check')
    require(len(result['images'])==2 and {r['Id'] for r in result['images']}==set(identities()) and
      all(r['sourceManifestSHA256']==bindings()['sourceManifestSHA256'] for r in result['images']) and
      next(r for r in result['images'] if r['Id']==identities()[1])['builderImageID']==identities()[0],'Linux image identity')
    app=result['application']
    require(set(app)=={'Id','image','name','started','status','health','networks'} and
      re.fullmatch('[0-9a-f]{64}',app['Id']) and app['name']=='/keysmith-keysmith-1' and
      app['status']=='running' and app['health']=='healthy','Linux application dependency')
    require(len(result['networks'])==3 and {r['Name'] for r in result['networks']}=={'proxy','bridge','none'},'Linux network dependencies')
    require(result['capacity']['cpus']>=2 and result['capacity']['availableMemory']>=2*1024**3 and
      result['capacity']['requiredScratchBytes']==0 and min(result['capacity']['workFree'],result['capacity']['dockerFree'])>=0,'Linux capacity')
    allowed=[['hostname'],D+['info','--format','{{.ID}}'],D+['info','--format','{{.DockerRootDir}}'],
      D+['context','inspect','default','--format','{{.Endpoints.docker.Host}}'],D+['image','inspect',*identities()],
      D+['ps','-aq','--no-trunc','--filter','name=^/keysmith-keysmith-1$'],
      D+['network','inspect','proxy','bridge','none'],D+['inspect',app['Id']]]
    require(result['commands'] and all(r['exitCode']==0 and r['arguments'] in allowed for r in result['commands']),
      'Linux check command failure/scope')
    return result

class Transport:
    def __init__(self):
        item=active().authority('transport');self.authority=parse(authenticated(pathlib.Path(item['path']),item['sha256']))
        require(self.authority.get('operationProfile')=='settlement-read-only-v1','Transport operation profile')
        validate_arguments(self.authority,bindings())
        self.last=None

    def probe(self):
        active().require_phase("read-only-host-check")
        a=self.authority
        validate_arguments(a,bindings())
        for key in ('ssh','config','knownHosts'):
            authenticated(a[key]['path'],a[key]['sha256'])
        probe=pathlib.Path(__file__).absolute().with_name('dk02_readonly_probe.py')
        script=authenticated(probe,active().code_hash('dk02_readonly_probe.py'))
        nonce=secrets.token_hex(16)
        command='/usr/bin/python3 -I -B -c "import base64;exec(base64.b64decode(\''+base64.b64encode(script).decode()+'\'))"'
        args=[a['ssh']['path'],*a['arguments'],command]
        try:r=subprocess.run(args,input=json.dumps({'nonce':nonce,'bindings':bindings(),'workflowSHA256':active().code_hash('workflow.py')}),capture_output=True,text=True,timeout=65)
        except subprocess.TimeoutExpired as error:raise TimeoutError('Authenticated SSH probe timeout') from error
        if r.returncode!=0:
            error=ValueError('Authenticated SSH probe failed exit '+str(r.returncode))
            error.exit_code=r.returncode
            error.diagnostic=r.stderr[-8192:]
            raise error
        require(len(r.stdout.encode())<=131072,'Oversized Linux check')
        result=validate(parse(r.stdout),nonce)
        self.last=result
        return result

    def host(self):self.probe()

    def execute_readonly(self,args,cwd=None,log=None,env=None):
        require(cwd is None and log is None and env is None,'Unapproved transport execution options')
        image_command=args==D+['image','inspect',*identities()] or (len(args)==6 and args[:5]==D+['image','inspect'] and args[5] in identities())
        ids_command=args==D+['ps','-aq','--no-trunc','--filter','name=^/keysmith-keysmith-1$']
        network_command=args==D+['network','inspect','proxy','bridge','none']
        inspect_command=len(args)==5 and args[:4]==D+['inspect'] and re.fullmatch('[0-9a-f]{64}',args[4])
        require(image_command or ids_command or network_command or inspect_command,'Unapproved remote Docker operation')
        p=self.probe()
        if image_command:
            wanted=args[5:]
            return json.dumps([{'Id':r['Id'],'Config':{'Labels':{'io.zevyrn.source-manifest-sha256':r['sourceManifestSHA256'],
                'io.zevyrn.builder-image-id':r['builderImageID']}}} for r in p['images'] if r['Id'] in wanted])
        if ids_command:return p['application']['Id']
        if network_command:return json.dumps(p['networks'])
        c=p['application'];require(args[4]==c['Id'],'Unapproved container inspection')
        return json.dumps([{'Id':c['Id'],'Name':c['name'],'Image':c['image'],
          'State':{'StartedAt':c['started'],'Status':c['status'],'Health':{'Status':c['health']}},
          'NetworkSettings':{'Networks':{n:{} for n in c['networks']}}}])
