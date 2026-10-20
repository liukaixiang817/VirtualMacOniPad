#!/usr/bin/env python3
"""Route six real strong VZ imports to unchanged app-private C++ definitions.

This emits inert Mach-O data only. It does not load, platform-port, sign,
deploy or execute VZ, a CPU or a guest. Native availability of the complete
transitive graph and original caller runtime behaviour remain separate gates.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('exact_hid_reader',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
spec=importlib.util.spec_from_file_location('exact_export_reader',HERE/'audit-modern-universalhid-current-stock-exports-v1.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
N=p.NODE
SOURCE=N/'universalhid-real-array-reexports-data-v1/candidate.json'
STAGED=N/'vz-genuine-strong-closure-design-v2/build-v1/bundle'
AUDIT=N/'universalhid-current-stock-extra-exports-audit-v1/audit.json'
TARGETS={
    23:'__ZTINSt3__119bad_expected_accessIvEE',
    24:'__ZNKSt3__119bad_expected_accessIvE4whatEv',
    401:'__ZNSt3__113__hash_memoryEPKvm',
    425:'__ZNSt3__123__atomic_monitor_globalEPKv',
    426:'__ZNSt3__126__atomic_wait_global_tableEPKvx',
    427:'__ZNSt3__132__atomic_notify_all_global_tableEPKv',
}
PINS={'VM27CxxProvider.dylib':'510239083d0098f2ede68f3fbb67d0c44e6dc25b40248e88c01de68596c2bac6',
      'ModernCPURuntimeCompat.dylib':'9847c7a79a5dcb29624f8e845c91ab01bc468d4cfab8275502142073500ee963'}

def exports(data):
    payload=None
    for cmd,at,size in p.commands(data):
        if cmd==0x80000033:payload=struct.unpack_from('<II',data,at+8)
        elif cmd==0x80000022 and payload is None:payload=struct.unpack_from('<II',data,at+40)
    assert payload and payload[1]
    off,size=payload;assert off+size<=len(data)
    return e.trie(data[off:off+size])

def runtime_contract():
    leaves={}
    for name,digest in PINS.items():
        file=STAGED/name;assert p.pin(file)['sha256']==digest
        raw=file.read_bytes();leaves[name]=dict(path=file,raw=raw,exports=exports(raw),dependencies=p.dependencies(raw))
    cp=leaves['VM27CxxProvider.dylib'];runtime=leaves['ModernCPURuntimeCompat.dylib']
    dependency=cp['dependencies'][1];assert dependency['ordinal']==2 and dependency['path']=='@rpath/ModernCPURuntimeCompat.dylib' and dependency['command']==12
    assert cp['dependencies'][0]['command']==0x8000001f and cp['dependencies'][0]['path']=='/usr/lib/libc++.1.dylib'
    proofs=[]
    for index,name in TARGETS.items():
        terminal=cp['exports'][name];assert terminal['flags']==8 and terminal['ordinal']==2 and not terminal['importedName']
        definition=runtime['exports'][name];assert not definition['flags']&8
        address=definition['offsetOrAbsoluteAddress']
        executable=any(s['address']<=address<s['address']+s['size'] and
            struct.unpack_from('<I',runtime['raw'],s['command']+56)[0]&4
            for s in p.segments(runtime['raw']))
        if index==23:
            assert not executable and any(s['address']<=address<s['address']+s['size']for s in p.segments(runtime['raw']))
        else:assert executable
        proofs.append(dict(index=index,symbol=name,trueNamedReexport=terminal,actualDefinition=definition,
            definitionProvider=p.pin(runtime['path']),nativeCallerABIHasNotBeenExecuted=True))
    assert len(proofs)==6
    return leaves,proofs

def validate(before,after,leaves):
    a=p.vz_reader.parse(before);b=p.vz_reader.parse(after)
    assert a['words']==b['words'] and a['nlists']==b['nlists']
    assert len(a['imports'])==len(b['imports'])==1056
    assert sum(not x['weak']for x in a['imports'])==sum(not x['weak']for x in b['imports'])==1011
    olddeps=p.dependencies(before);deps=p.dependencies(after)
    assert deps[:-1]==olddeps and len(deps)==61
    assert deps[-1]['ordinal']==61 and deps[-1]['path']=='@loader_path/CP' and deps[-1]['command']==12
    assert deps[-1]['size']==40
    for left,right in zip(a['imports'],b['imports'],strict=True):
        expected={**left,'ordinal':61}if left['index']in TARGETS else left
        assert right==expected
        if left['index']in TARGETS:
            assert left['name']==TARGETS[left['index']] and left['ordinal']==18 and not left['weak'] and left['addend']==0
    for seg in p.segments(before):
        for s in seg['sections']:
            if not s['fileoff']or s['flags']&255 in(1,12):continue
            at=s['fileoff'];size=s['size'];assert before[at:at+size]==after[at:at+size],s['name']
    for name in PINS:assert p.pin(leaves[name]['path'])['sha256']==PINS[name]
    return a,b

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(N)and not out.exists();out.mkdir()
    assert p.pin(SOURCE)['sha256']=='feb66a42d89aefd265662407b84d18e357089c69cd3d5a6c2e1d14444c5caa6f'
    assert p.pin(AUDIT)['sha256']=='14e1022d146f3b70d2869b7c65a2312018e1c779bce1202fa9161609eba5ec80'
    source=json.loads(SOURCE.read_bytes());record=next(x['candidate']for x in source['images']if x['name']=='Virtualization')
    file=Path(record['path']);assert p.pin(file)==record;before=file.read_bytes();data=bytearray(before)
    audit=json.loads(AUDIT.read_bytes());rows=next(x['imports']for x in audit['auditedImages']if x['name']=='Virtualization')
    for index,name in TARGETS.items():
        row=next(x for x in rows if x['index']==index);assert row['symbol']==name and row['proof']['status']=='actualExportAbsent' and row['dependency']=='/usr/lib/libc++.1.dylib'
    leaves,proofs=runtime_contract();ordinal=p.append_dependency(data,'@loader_path/CP');assert ordinal==61
    imports=p.vz_reader.parse(before)['imports'];routes=[]
    for row in imports:
        if row['index']not in TARGETS:continue
        assert row['name']==TARGETS[row['index']] and row['ordinal']==18 and not row['weak'] and row['addend']==0
        word=struct.unpack_from('<I',data,row['at'])[0];struct.pack_into('<I',data,row['at'],(word&~255)|ordinal)
        routes.append(dict(index=row['index'],symbol=row['name'],at=row['at'],oldOrdinal=18,newOrdinal=ordinal))
    after=bytes(data);a,b=validate(before,after,leaves)
    candidate=out/'VZ27.cxx-six-strong.mac.inert.macho-data';candidate.write_bytes(after)
    process=subprocess.run(['xcrun','dyld_info','-validate_only',str(candidate)],capture_output=True)
    (out/'dyld.stdout').write_bytes(process.stdout);(out/'dyld.stderr').write_bytes(process.stderr);assert process.returncode==0
    copies=[]
    for alias,name in [('CP','VM27CxxProvider.dylib'),('ModernCPURuntimeCompat.dylib','ModernCPURuntimeCompat.dylib')]:
        target=out/(alias+'.unchanged-ios-provider.inert.macho-data');target.write_bytes(leaves[name]['raw']);assert p.pin(target)['sha256']==PINS[name]
        copies.append(dict(alias=alias,intendedLoadPath='@loader_path/'+alias,source=p.pin(leaves[name]['path']),candidate=p.pin(target),codeBytesUnchanged=True))
    negatives=[]
    def rejected(name,blob):
        try:validate(before,blob,leaves)
        except (AssertionError,ValueError,struct.error,KeyError):negatives.append(name);return
        raise AssertionError('counterexample accepted: '+name)
    for route in routes:
        for kind,mask in [('old-provider',18),('weak',None),('flat',254)]:
            q=bytearray(after);word=struct.unpack_from('<I',q,route['at'])[0]
            struct.pack_into('<I',q,route['at'],word|256 if mask is None else(word&~255)|mask);rejected(str(route['index'])+'-'+kind,bytes(q))
    q=bytearray(after);struct.pack_into('<I',q,p.dependencies(after)[-1]['at'],0x80000018);rejected('weak-new-dependency',bytes(q))
    for name in ('__text','__swift5_types'):
        sections=[s for g in p.segments(before)for s in g['sections']if s['name']==name and s['size']and s['fileoff']]
        assert sections;q=bytearray(after);q[sections[0]['fileoff']]^=1;rejected('changed-'+name,bytes(q))
    report=dict(schema='Six actual absent Cxx imports strong route to unchanged genuine definitions v1',sourceCandidate=p.pin(SOURCE),frontendSource=record,
        stockAbsenceAudit=p.pin(AUDIT),frontendCandidate=p.pin(candidate),routes=routes,definitionContracts=proofs,unchangedRuntimeProviders=copies,
        strongImportsPreserved=1011,importCount=len(a['imports']),codeMetadataWitnessPACAndNlistPreserved=True,
        atomicThreeImportsUseOneActualWaitingTable=True,dyldValidationExit=process.returncode,negativeCasesRejected=negatives,
        originalCallerRuntimeABIValidated=False,currentCompleteProviderDependencyGraphValidated=False,completeOriginal27MetadataPreserved=False,
        fullCurrentLoadGraphProven=False,platformPorted=False,frontendCodeSigned=False,nativeExecuted=False,deviceOperations=0,originalVZLoaded=False,full27Backend=False)
    p.save(out/'candidate.json',report)
    files=[Path(__file__),SOURCE,AUDIT,file,candidate,out/'candidate.json']+[Path(x[k]['path'])for x in copies for k in('source','candidate')]
    p.save(out/'freeze.json',dict(files=[p.pin(f)for f in files],nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),routedStrongImports=len(routes),negativeCasesRejected=len(negatives))))

if __name__=='__main__':main()
