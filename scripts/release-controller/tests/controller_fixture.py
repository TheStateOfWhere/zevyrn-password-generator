"""Synthetic current-JS-compiler complete evidence; never invokes scanner/Docker."""
from pathlib import Path
import ast,datetime as dt,hashlib,io,json,tarfile
from test_js_compiler import CompilerTests
from test_whiteouts import entry,tar_bytes
from test_image_metadata import fixture as image_fixture

H=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:json.dumps(v,sort_keys=True).encode()

def make(root):
 root=Path(root);root.mkdir()
 def write(name,data):
  p=root/name;p.parent.mkdir(exist_ok=True,parents=True);p.write_bytes(data if isinstance(data,bytes) else J(data))
 now=dt.datetime.now(dt.timezone.utc);t=lambda n:(now+dt.timedelta(minutes=n)).isoformat()
 manifest=b'synthetic-controller-current-source';source=H(manifest);write('source-manifest.json',manifest)
 packages={'nginx':'1.30.6-r1','libexpat':'2.9.0-r0','zlib':'1.3.2-r1','pcre2':'10.49-r0','tiff':'4.7.2-r0','libpng':'1.6.59-r0','nghttp2-libs':'1.70.0-r0'}
 layer=tar_bytes([entry('lib/apk/db/installed',''.join('P:'+n+'\nV:'+v+'\nA:x86_64\n\n' for n,v in packages.items()).encode())])
 CompilerTests.setUpClass();builds={}
 for kind in ('builder','runtime'):
  settings=image_fixture(kind=='runtime')['Config'];settings.setdefault('Labels',{})['io.zevyrn.source-manifest-sha256']=source
  layers=[layer]+([CompilerTests.base] if kind=='builder' else [])
  refs=[str(i)+'/layer.tar' for i in range(len(layers))]
  cfg=J({'os':'linux','architecture':'amd64','config':settings,'rootfs':{'type':'layers','diff_ids':['sha256:'+H(v) for v in layers]}})
  data=tar_bytes([entry('manifest.json',J([{'Config':'config.json','Layers':refs}])),entry('config.json',cfg),*[entry(n,b) for n,b in zip(refs,layers)]])
  write(kind+'.tar',data);builds[kind]={'image':{'id':'sha256:'+H(cfg)},'archive':kind+'.tar','archiveSHA256':H(data)}
 q={'runID':'controller-synthetic-test','sourceManifestSHA256':source,'expectedDaemonID':'61e7a09e-8ce6-436a-af77-658cb0f61bd6'}
 write('qualification.json',q);write('builds.json',builds)
 images={k:{'imageID':v['image']['id'],'archiveSHA256':v['archiveSHA256']} for k,v in builds.items()}
 from qualification_evidence import SCANNER_POLICY_SHA256
 database=b'synthetic-scanner-database';binary=b'synthetic-scanner-binary'
 context={'runID':q['runID'],'sourceManifestSHA256':source,'startedUTC':t(-10),'scannerVersion':'0.76.0','scannerBinarySHA256':H(binary),'dbSHA256':H(database),'scannerPolicySHA256':SCANNER_POLICY_SHA256,'images':images}
 write('evidence-context.json',context)
 tree=ast.parse((Path(__file__).parents[1]/'scan-images.py').read_bytes());funcs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('digest','packages','archive_name','archive_inventory')]
 ns={'Path':Path,'R':root,'hashlib':hashlib,'json':json,'tarfile':tarfile,'gzip':__import__('gzip'),'write':write}
 exec(compile(ast.Module(body=funcs,type_ignores=[]),'reviewed fixture archive functions','exec'),ns)
 for kind in builds:ns['archive_inventory'](kind,builds[kind])
 for kind in builds:
  report={'SchemaVersion':2,'ArtifactType':'container_image','CreatedAt':t(-3),'Metadata':{'ImageID':images[kind]['imageID']},'Results':[{'Target':'image (alpine)','Class':'os-pkgs','Type':'alpine','Packages':[{'Name':n,'Version':v} for n,v in packages.items()]}]}
  if kind=='builder':report['Results'].append({'Target':'Node.js','Class':'lang-pkgs','Type':'node-pkg','Packages':[{'Name':n,'Version':v,'FilePath':'app/node_modules/'+p+'/package.json'} for n,v,p in [('@typescript/typescript6','6.0.2','@typescript/typescript6'),('typescript','6.0.3','@typescript/old'),('playwright','1.62.1','playwright'),('playwright-core','1.62.1','playwright-core')]]})
  write(kind+'-raw-scan.json',report)
  rec={**{k:context[k] for k in ('runID','sourceManifestSHA256','scannerVersion','scannerBinarySHA256','dbSHA256','scannerPolicySHA256')},**images[kind],'reportSHA256':H(J(report)),'startedUTC':t(-4),'finishedUTC':t(-2)}
  write(kind+'-scan-receipt.json',rec)
 bom={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'metadata':{'timestamp':t(-3),'tools':{'components':[{'type':'application','name':'trivy','version':'0.76.0'}]},'component':{'type':'container','name':'runtime','properties':[{'name':'aquasecurity:trivy:ImageID','value':images['runtime']['imageID']}]}},'components':[{'type':'library','name':n,'version':v,'purl':'pkg:apk/alpine/'+n+'@'+v+'?arch=x86_64'} for n,v in packages.items()],
 'externalReferences':[{'type':'website','url':'https://example.org/\u4f8b'}],
 'signature':{'algorithm':'https://example.org/synthetic-algorithm','value':'synthetic-format-only'}}
 write('runtime-sbom.cdx.json',bom)
 receipt={**{k:context[k] for k in ('runID','sourceManifestSHA256','scannerVersion','scannerBinarySHA256','dbSHA256','scannerPolicySHA256')},**images['runtime'],'sbomSHA256':H(J(bom)),'sourceReportSHA256':H((root/'runtime-raw-scan.json').read_bytes()),'startedUTC':t(-4),'finishedUTC':t(-2)}
 write('runtime-sbom-receipt.json',receipt)
 write('trivy-cache/db/trivy.db',database);db={'Version':2,'UpdatedAt':t(-60),'DownloadedAt':t(-9),'NextUpdate':t(60)}
 for phase in ('start','end'):write('scanner-db-'+phase+'.json',{'metadata':db,'databaseSHA256':H(database)})
 write('tools/trivy',binary);write('scanner-provenance.json',{'releaseArchiveSHA256':'e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7','binarySHA256':H(binary)})
 write('scanner-version.json',{'Version':'0.76.0'})
 write('filesystem-equivalence.json',{'passed':True,'runID':q['runID'],'sourceManifestSHA256':source,'exports':{'runtime':images['runtime']}})
 return {'runID':q['runID'],'sourceManifestSHA256':source,'qualificationSHA256':H((root/'qualification.json').read_bytes()),'buildsSHA256':H((root/'builds.json').read_bytes()),'expectedDaemonID':q['expectedDaemonID']}
