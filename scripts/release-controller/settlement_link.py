"""Narrow integration into existing settlement/final phases; no phase dispatcher."""
import hashlib
import json
from pathlib import Path
import stat
import sys


def plain(path):
    path=Path(path).absolute()
    for part in [*reversed(path.parents),path]:
        info=part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('LINKED_SETTLEMENT_PATH')
    return path


def authenticated(path,digest):
    data=plain(path).read_bytes()
    if hashlib.sha256(data).hexdigest()!=digest:
        raise ValueError('SETTLEMENT_IDENTITY_MISMATCH: '+str(path))
    return data


def context(C,root):
    policy=json.loads(authenticated(C['SETTLEMENT_POLICY'],C['SETTLEMENT_POLICY_SHA256']))
    C['require'](str(root)==policy['originalRoot'],'Settlement attempt substitution')
    C['require'](str(Path(sys.executable))==policy['interpreter']['path'],'Settlement interpreter path')
    authenticated(sys.executable,policy['interpreter']['sha256'])
    for row in policy['proposalFiles']:
        authenticated(row['path'],row['sha256'])
    entry=policy['entrypoint']
    data=authenticated(entry['path'],entry['sha256'])
    scope={'__file__':entry['path'],'__name__':'authenticated_supplemental_settlement_contract'}
    exec(compile(data,entry['path'],'exec'),scope)
    assessment=scope['require_settlement'](Path(policy['claim']))
    C['require'](assessment.get('browserEvidenceEligible') is True and
                 assessment['gate']=='browser-testing.realClipboardPasteBack' and
                 assessment['originalResult']=='FAILED_PRESERVED' and
                 assessment['otherQualificationGatesSuperseded']==[], 'Supplemental browser contract failed')
    output=Path(policy['outputRoot'])
    C['require'](output.is_absolute() and not output.is_relative_to(root) and
                 not root.is_relative_to(output) and output.parent.is_dir(), 'Overlapping settlement output')
    plain(output.parent)
    if output.exists():
        plain(output)
        C['require'](output.is_dir(),'Invalid settlement output')
        allowed={'settlement-attempt.json','settlement-completed.json','settlement-failed.json',
                 'final-attempt.json','final-completed.json','final-failed.json','settled.json',
                 'browser-evidence-integration.json','consolidated-qualification.json','security-evidence-integration.json'}
        for p in output.iterdir():
            plain(p)
            C['require'](p.is_file() and p.name in allowed,'Unexpected settlement output file')
    return {'policy':policy,'assessment':assessment,'output':output,
            'proof':{'executionID':root.name,'settlementExecutionID':policy['settlementExecutionID'],
                     'qualificationRunID':C['RUN'],'sourceManifestSHA256':C['SOURCE'],'images':C['IMAGES'],
                     'policySHA256':C['SETTLEMENT_POLICY_SHA256'],'browserAssessment':assessment,
                     'historicalFailurePreserved':True,'originalBrowserCompletionFabricated':False}}


def completed(C,ctx,name):
    out=ctx['output']; p=out/(name+'-completed.json')
    C['require'](p.is_file(),'Required settlement predecessor incomplete: '+name)
    a=C['read'](out/(name+'-attempt.json')); r=C['read'](p)
    for doc in (a,r):
        C['require'](doc.get('executionID')==ctx['proof']['executionID'] and
                     doc.get('settlementExecutionID')==ctx['policy']['settlementExecutionID'] and
                     doc.get('qualificationRunID')==C['RUN'] and doc.get('images')==C['IMAGES'] and
                     doc.get('sourceManifestSHA256')==C['SOURCE'] and
                     doc.get('policySHA256')==C['SETTLEMENT_POLICY_SHA256'],'Settlement receipt identity')
    C['require'](a['startedUTC']==r['startedUTC'] and r['finishedUTC']>=a['startedUTC'], 'Settlement receipt interval')
    C['require'](set(r['artifacts'])==set(C['artifacts'](name)), 'Incomplete settlement evidence inventory')
    for n,h in r['artifacts'].items():
        C['require'](C['sha'](C['safe'](out,n))==h,'Settlement artifact changed: '+n)
    return r


def progress(C,root,name):
    C['require'](name in ('settlement','final'),'Supersession outside settlement boundary')
    ctx=context(C,root)
    # Only the precise browser failure/attempt may use supplemental completion.
    failures={p.name for p in root.glob('*-failed.json')}
    C['require'](failures=={'browser-testing-failed.json'}, 'Unrelated or missing qualification failure')
    for p in root.glob('*-attempt.json'):
        phase_name=p.name[:-len('-attempt.json')]
        C['require'](phase_name in C['ORDER'],'Unexpected phase attempt')
        if phase_name!='browser-testing': C['completed'](root,phase_name)
    for predecessor in C['PREDECESSORS'][name]:
        if predecessor=='browser-testing': continue # exact contract verified above
        if predecessor=='settlement': completed(C,ctx,predecessor)
        else: C['completed'](root,predecessor)
    out=ctx['output']
    if out.exists():
        C['require'](not list(out.glob('*-failed.json')),'Failed settlement cannot be retried')
        for p in out.glob('*-attempt.json'):
            phase_name=p.name[:-len('-attempt.json')]
            C['require'](phase_name in ('settlement','final'),'Unexpected settlement phase')
            completed(C,ctx,phase_name)
    return ctx


def phase(C,root,name,action):
    ctx=progress(C,root,name); out=ctx['output']
    if not out.exists(): out.mkdir() # fresh separate output only after all prerequisites
    start=C['utc']()
    identity={'executionID':root.name,'settlementExecutionID':ctx['policy']['settlementExecutionID'],
              'qualificationRunID':C['RUN'],'sourceManifestSHA256':C['SOURCE'],'images':C['IMAGES'],
              'policySHA256':C['SETTLEMENT_POLICY_SHA256'],'startedUTC':start}
    C['save'](out/(name+'-attempt.json'),identity)
    try: result=action()
    except BaseException as error:
        C['save'](out/(name+'-failed.json'),{**identity,'exception':type(error).__name__,
                    'message':str(error),'utc':C['utc']()})
        raise
    C['save'](out/(name+'-completed.json'),{**identity,'finishedUTC':C['utc'](),'result':result,
             'artifacts':{n:C['sha'](C['safe'](out,n)) for n in C['artifacts'](name)}})
    return result
