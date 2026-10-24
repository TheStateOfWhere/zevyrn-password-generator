"""Bounded Docker-save/OCI identity resolution; no extraction or network access.

The caller supplies its existing safe regular-member reader. No general archive
framework or filesystem/layer interpreter is introduced here.
"""
import hashlib
import json
import re

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
LAYERS = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip'}


def check(value, reason):
    if not value:
        raise ValueError(reason)


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def document(data, label):
    def pairs(items):
        obj = {}
        for key, value in items:
            check(key not in obj, 'Duplicate JSON key in ' + label)
            obj[key] = value
        return obj
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ValueError('Malformed ' + label) from error


def descriptor(value, allowed):
    check(isinstance(value, dict), 'Malformed OCI descriptor')
    check(value.get('mediaType') in allowed, 'Unsupported OCI descriptor media type')
    check(isinstance(value.get('digest'), str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value['digest']), 'Malformed OCI descriptor digest')
    check(type(value.get('size')) is int and value['size'] > 0, 'Malformed OCI descriptor size')
    if 'platform' in value:
        platform = value['platform']
        check(isinstance(platform, dict) and all(isinstance(platform.get(k), str) and platform[k] for k in ('os','architecture')), 'Malformed OCI descriptor platform')
        if 'variant' in platform:
            check(isinstance(platform['variant'], str), 'Malformed OCI platform variant')
    if 'annotations' in value:
        check(isinstance(value['annotations'], dict) and all(isinstance(k,str) and isinstance(v,str) for k,v in value['annotations'].items()), 'Malformed OCI descriptor annotations')
    return value


def resolve_export(outer_file, names, expected_id):
    check(isinstance(expected_id,str) and re.fullmatch(r'sha256:[0-9a-f]{64}',expected_id), 'Malformed expected image identity')
    legacy = None
    if 'manifest.json' in names:
        entries = document(outer_file('manifest.json').read(), 'Docker archive manifest')
        check(isinstance(entries,list) and len(entries)==1 and isinstance(entries[0],dict), 'Malformed Docker archive manifest')
        legacy = entries[0]
        check(isinstance(legacy.get('Config'),str) and isinstance(legacy.get('Layers'),list) and all(isinstance(p,str) for p in legacy['Layers']), 'Malformed Docker archive references')
    present = {'oci-layout','index.json'} & set(names)
    if not present:
        check(legacy is not None, 'Unsupported archive format')
        config_bytes = outer_file(legacy['Config']).read()
        if digest(config_bytes)!=expected_id:raise AssertionError('Unexpected image configuration identity')
        config = document(config_bytes,'image configuration')
        if not isinstance(config,dict) or (config.get('os'),config.get('architecture'))!=('linux','amd64'):raise AssertionError('Unexpected configuration platform')
        return {'config':config,'configReference':legacy['Config'],'layerReferences':legacy['Layers'],
                'chain':{'format':'docker-save-config-id','imageID':expected_id,'configurationDigest':expected_id,'configurationReference':legacy['Config']}}
    check(present=={'oci-layout','index.json'}, 'Incomplete OCI image layout')
    layout=document(outer_file('oci-layout').read(),'OCI layout')
    check(isinstance(layout,dict) and layout.get('imageLayoutVersion')=='1.0.0','Unsupported OCI layout version')

    def index_doc(raw):
        value=document(raw,'OCI index')
        check(isinstance(value,dict) and type(value.get('schemaVersion')) is int and value['schemaVersion']==2 and value.get('mediaType')==INDEX and isinstance(value.get('manifests'),list), 'Malformed OCI index')
        return value

    def blob(desc, allowed):
        descriptor(desc,allowed)
        path='blobs/sha256/'+desc['digest'].split(':',1)[1]
        try:raw=outer_file(path).read()
        except (KeyError,AttributeError,ValueError) as error:raise ValueError('Missing or unsafe OCI referenced blob') from error
        check(len(raw)==desc['size'],'OCI descriptor size mismatch')
        check(digest(raw)==desc['digest'],'OCI descriptor digest mismatch')
        return raw,path

    top_raw=outer_file('index.json').read();top=index_doc(top_raw)
    for item in top['manifests']:descriptor(item,{INDEX,MANIFEST})
    matches=[x for x in top['manifests'] if x['digest']==expected_id]
    if digest(top_raw)==expected_id:
        check(not matches,'Ambiguous OCI root identity')
        root=top;root_type=INDEX
    else:
        check(len(matches)==1,'Missing or duplicated expected OCI root identity')
        raw,_=blob(matches[0],{INDEX,MANIFEST});root_type=matches[0]['mediaType']
        root=index_doc(raw) if root_type==INDEX else document(raw,'OCI manifest')
    ignored=[]
    if root_type==INDEX:
        selected=[];seen=set()
        for item in root['manifests']:
            descriptor(item,{MANIFEST})
            check(item['digest'] not in seen,'Duplicate OCI platform descriptor')
            seen.add(item['digest'])
            member_raw,_=blob(item,{MANIFEST})  # Includes non-target entries.
            member_doc=document(member_raw,'OCI manifest')
            check(isinstance(member_doc,dict) and type(member_doc.get('schemaVersion')) is int and member_doc['schemaVersion']==2 and member_doc.get('mediaType')==MANIFEST and isinstance(member_doc.get('config'),dict) and isinstance(member_doc.get('layers'),list),'Malformed OCI manifest')
            platform=item.get('platform')
            check(platform is not None,'Missing OCI platform metadata')
            if platform.get('os')=='linux' and platform.get('architecture')=='amd64':
                check(platform.get('variant') in (None,'','v1'),'Unsupported target platform variant')
                selected.append(item)
            else:ignored.append({'digest':item['digest'],'platform':platform,'annotations':item.get('annotations',{})})
        check(len(selected)==1,'Missing or ambiguous target platform selection')
        selected_desc=selected[0];manifest_raw,_=blob(selected_desc,{MANIFEST})
        manifest=document(manifest_raw,'OCI manifest');manifest_digest=selected_desc['digest']
    else:
        manifest=root;manifest_digest=expected_id
        if matches[0].get('platform') is not None:
            platform=matches[0]['platform']
            check(platform.get('os')=='linux' and platform.get('architecture')=='amd64' and platform.get('variant') in (None,'','v1'),'Unexpected manifest descriptor platform')
    check(isinstance(manifest,dict) and type(manifest.get('schemaVersion')) is int and manifest['schemaVersion']==2 and manifest.get('mediaType')==MANIFEST and isinstance(manifest.get('layers'),list),'Malformed OCI manifest')
    config_raw,config_path=blob(manifest.get('config'),{CONFIG})
    config=document(config_raw,'image configuration')
    check(isinstance(config,dict) and (config.get('os'),config.get('architecture'))==('linux','amd64'),'Unexpected configuration platform')
    layers=[]
    for item in manifest['layers']:
        _,path=blob(item,LAYERS);layers.append(path)
    check(isinstance(config.get('rootfs'),dict) and config['rootfs'].get('type')=='layers' and isinstance(config['rootfs'].get('diff_ids'),list) and len(config['rootfs']['diff_ids'])==len(layers),'Malformed configuration rootfs/layer relationship')
    if legacy is not None:
        check(legacy['Config']==config_path and legacy['Layers']==layers,'Docker/OCI representation mismatch')
    return {'config':config,'configReference':config_path,'layerReferences':layers,
            'chain':{'format':'oci-layout','imageID':expected_id,'rootMediaType':root_type,
                     'platformManifestDigest':manifest_digest,'configurationDigest':manifest['config']['digest'],
                     'configurationSize':manifest['config']['size'],'configurationReference':config_path,'selectedPlatform':'linux/amd64',
                     'descriptorDigestsAndSizesVerified':True,'nonTargetDescriptors':ignored}}
