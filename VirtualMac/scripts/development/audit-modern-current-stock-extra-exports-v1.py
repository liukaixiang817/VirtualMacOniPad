#!/usr/bin/env python3
"""Join current bounded captures and audit exact strong import ownership.

Only immutable captures and inert candidates are parsed. Uncaptured reexports
stay unknown. This is definition evidence, never a runtime load or boot claim.
"""
import argparse
import base64
import collections
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
sys.dont_write_bytecode = True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('primary_current_stock',HERE/'audit-modern-universalhid-current-stock-exports-v1.py')
primary=importlib.util.module_from_spec(spec);spec.loader.exec_module(primary)
p=primary.p;N=p.NODE

def checked_capture(directory,manifest,headers):
    receipt=json.loads((directory/'receipt.json').read_bytes())
    assert receipt['mainCacheUUID']=='1995ea169d0a33a0b78962cf99891168'
    assert receipt['transportExit']==0 and receipt['allHeaderPinsMatchBeforeAndAfter']
    assert receipt['manifestSHA256']==p.pin(manifest)['sha256'] and receipt['headersSHA256']==p.pin(headers)['sha256']
    assert not any(receipt[k]for k in ('deviceWrites','nativeCPUCalls','newFrameworksLoaded'))
    assert receipt['scriptSHA256']==p.pin(directory/'script.sh')['sha256']
    assert receipt['stdoutSHA256']==p.pin(directory/'stdout')['sha256'] and receipt['stderrSHA256']==p.pin(directory/'stderr')['sha256']
    output=(directory/'stdout').read_bytes();assert output.endswith(b'FINAL_CACHE_HEADERS_MATCH\n')
    plan=json.loads(manifest.read_bytes())['ranges'];assert len(plan)==len(receipt['ranges'])
    for row,capture in zip(plan,receipt['ranges']):
        assert all(capture[k]==row[k]for k in ('name','cache','offset','length'))
        path=Path(capture['path']);assert path.parent==directory and path.name==row['name']+'.bin'
        assert p.pin(path)['sha256']==capture['sha256'] and path.stat().st_size==row['length']
        block=re.findall(rb'BEGIN_BASE64 '+row['name'].encode()+rb'\n([A-Za-z0-9+/=\n]+)\nEND_BASE64 '+row['name'].encode()+rb'\n',output);assert len(block)==1
        assert base64.b64decode(re.sub(rb'\s',b'',block[0]),validate=True)==path.read_bytes()
    assert sum(x['length']for x in plan)==receipt['requestedBytes']<=4*1024*1024
    return receipt

def join_capture(images,group,headers):
    commands=N/('ipad-current-cache-'+group+'-commands-readonly-v1')
    exports=N/('ipad-current-cache-'+group+'-exports-readonly-v1')
    cm=N/('ipad-current-cache-'+group+'-commands-manifest-v1.json')
    em=N/('ipad-current-cache-'+group+'-exports-manifest-v1.json')
    checked_capture(commands,cm,headers);checked_capture(exports,em,headers)
    manifest=json.loads(em.read_bytes());head=json.loads(headers.read_bytes())
    mapping_headers={x['name']:x for x in head['headers']}
    assert len(manifest['ranges'])==len(manifest['mappedActualLoadCommands'])
    pins=[p.pin(x)for x in (commands/'receipt.json',exports/'receipt.json',cm,em,headers,commands/'reader-source.py',exports/'reader-source.py')]
    for row,declared in zip(manifest['ranges'],manifest['mappedActualLoadCommands']):
        stem=row['name'].removesuffix('-exports');cp=commands/(stem+'-commands.bin');header=cp.read_bytes()
        assert len(header)==32+struct.unpack_from('<I',header,20)[0]
        path=uuid=export=None
        for cmd,at,size in p.commands(header):
            if cmd==13:
                offset=struct.unpack_from('<I',header,at+8)[0];path=header[at+offset:at+size].split(b'\0')[0].decode()
            elif cmd==27:uuid=header[at+8:at+24].hex()
            elif cmd==0x80000033:export=struct.unpack_from('<II',header,at+8)
        if export is None:
            for cmd,at,size in p.commands(header):
                if cmd==0x80000022:export=struct.unpack_from('<II',header,at+40)
        assert path and uuid and export and path==declared['image'] and uuid==declared['imageUUID']
        assert export==(declared['originalImageExportOffset'],row['length'])
        segment=next(x for x in p.segments(header)if x['name']=='__LINKEDIT')
        va=segment['address']+export[0]-segment['fileoff'];assert va==declared['exportVA']
        maps=mapping_headers[row['cache']]['maps'];matches=[m for m in maps if m['address']<=va and va+row['length']<=m['address']+m['size']];assert len(matches)==1
        mapping=matches[0];assert row['offset']==mapping['fileOffset']+va-mapping['address']
        blob=exports/(stem+'-exports.bin');tree=primary.trie(blob.read_bytes());deps=p.dependencies(header)
        for e in tree.values():
            if e['flags']&8:assert 1<=e['ordinal']<=len(deps)
        key=primary.canonical_path(path);assert key not in images
        images[key]=dict(path=path,UUID=uuid,header=p.pin(cp),trie=p.pin(blob),exports=tree,dependencies=deps,currentCapture=True)
        pins.extend([p.pin(cp),p.pin(blob)])
    return pins

def audit(output):
    images=primary.captured_images();pins=join_capture(images,'system',N/'ipad-current-cache-system-headers-v1/headers.json')
    pins+=join_capture(images,'stock-extra',N/'ipad-current-cache-stock-extra-headers-v1/headers.json')
    source=json.loads((N/'universalhid-current-stock-exports-audit-v2/audit.json').read_bytes())
    result=[]
    for original in source['auditedImages']:
        file=Path(original['image']['path']);assert p.pin(file)==original['image']
        data=file.read_bytes()
        if original['name']=='Virtualization':
            parsed=p.vz_reader.parse(data);imports=parsed['imports'];deps={x['ordinal']:x['name']for x in parsed['deps']}
        else:
            imports=p.imports(data)['imports'];deps={x['ordinal']:x['path']for x in p.dependencies(data)}
        rows=[]
        for item in imports:
            if item['weak']:continue
            assert item['ordinal']>0 and item['ordinal']in deps
            owner=deps[item['ordinal']];proof=primary.resolve(images,owner,item['name'])
            rows.append(dict(index=item['index'],symbol=item['name'],ordinal=item['ordinal'],dependency=owner,proof=proof))
        counts=dict(collections.Counter(x['proof']['status']for x in rows))
        result.append(dict(name=original['name'],image=p.pin(file),strongImports=len(rows),counts=counts,imports=rows))
        pins.append(p.pin(file))
    # Reject cycles, absent names and uncaptured owners without inventing a
    # fallback. A named reexport must follow its actual provider and name.
    negative=primary.resolve(images,'/usr/lib/libobjc.A.dylib','__VM27_not_a_real_export__')
    assert negative['status']=='actualExportAbsent'
    assert primary.resolve(images,'@loader_path/UniversalHID27.dylib','_swift_getWitnessTable')['status']=='uncapturedOwner'
    proof=primary.resolve(images,'/usr/lib/libSystem.B.dylib','_memmove');assert proof['status']=='actualDirectExport'
    proof2=primary.resolve(images,'/usr/lib/libSystem.B.dylib','_malloc_size');assert proof2['status']=='actualDirectExport'
    report=dict(schema='Twelve current exact stock export captures audit v1',currentCacheUUID=source['currentCacheUUID'],imageCount=len(images),
        images=[{k:v for k,v in x.items()if k!='exports'}|dict(exportCount=len(x['exports']))for x in images.values()],auditedImages=result,
        arraySystemReexportExamples=[proof,proof2],allCapturedTriesComplete=True,stockTransitiveClosureProven=False,
        privateProvidersIncluded=False,metadataCompatibilityProven=False,originalVZLoaded=False,nativeExecuted=False,full27Backend=False,
        deviceWrites=0,nativeCPUCalls=0,definitionEvidenceRequiresIndependentCaptureReceiptReview=True)
    assert len(images)==12
    p.save(output/'audit.json',report)
    pins+=[p.pin(x)for x in (Path(__file__),HERE/'audit-modern-universalhid-current-stock-exports-v1.py',N/'universalhid-current-stock-exports-audit-v2/audit.json',output/'audit.json')]
    p.save(output/'freeze.json',dict(files=pins,nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(output/'audit.json'),counts=[dict(name=x['name'],counts=x['counts'])for x in result])))

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
    output=args.output.resolve();assert output.is_relative_to(N)and not output.exists();output.mkdir();audit(output)
