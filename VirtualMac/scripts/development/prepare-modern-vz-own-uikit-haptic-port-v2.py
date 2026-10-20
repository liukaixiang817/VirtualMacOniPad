#!/usr/bin/env python3
"""Two explicit ENOTSUP host-haptic contracts; preserve original task cleanup."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('haptic_q',HERE/'prepare-modern-vz-own-uikit-event-init-port-v2.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q);f,p,s,n=q.f,q.p,q.s,q.n
SELECTED={315:('_SLSMainConnectionID','_VM27NoHapticV1'),312:('_SLSActuateDeviceWithPattern','_VM27RejectHapticV1')}
TASK=0x2260b7358-0x225f36000;TASK_LEN=296
# The actual LC26 original task starts at 0x2260b7358, base 0x225f36000.
assert TASK==0x2260b7358-0x225f36000

def transform(before):
    result=bytearray(before);schema=q.import_records(before,p.commands);ranges=q.strings(before)
    for ix,(old,new)in SELECTED.items():
        row=schema['imports'][ix];assert row['name']==old and row['ordinal']==52 and not row['weak']and row['addend']==0
        off,length=ranges[ix];assert len(new)+1<=length
        assert all(oi==ix or address+count<=off or off+length<=address for oi,(address,count)in ranges.items())
        result[off:off+length]=new.encode()+bytes(length-len(new));result[row['command']]=29
    return bytes(result)

def validate(before,after):
    assert after==transform(before);a,b=p.vz_reader.parse(before),p.vz_reader.parse(after)
    assert a['words']==b['words']and a['nlists']==b['nlists']and a['segments']==b['segments']and a['header']==b['header']and a['commands']==b['commands']
    old,new=q.import_records(before,p.commands),q.import_records(after,p.commands)
    assert new==dict(old,imports=[dict(row,name=SELECTED[row['index']][1],ordinal=29)if row['index']in SELECTED else row for row in old['imports']])
    assert len(new['imports'])==1056 and sum(not row['weak']for row in new['imports'])==1011
    assert not any(row['name']in [x[0]for x in SELECTED.values()]for row in b['nlists'])
    for seg in p.segments(before):
        for sec in seg['sections']:
            if sec['fileoff']and sec['size']and sec['flags']&255 not in(1,12,18):
                off,length=sec['fileoff'],sec['size'];assert before[off:off+length]==after[off:off+length]
    remaining=[row for row in new['imports']if row['ordinal']==52 and not row['weak']];assert len(remaining)==6
    return dict(newUnsupportedContracts=2,allOriginalInstructionSectionsPreserved=True,originalHapticTaskWholeBytesPreserved=True,
        allOriginalObjCAndSwiftMetadataNlistsAndDependencyCommandsPreserved=True,totalImports=1056,strongImports=1011,
        allChainedWholePACWordsPreserved=len(a['words']),changedBytes=sum(x!=y for x,y in zip(before,after)),remainingSkyLightStrongImports=remaining)

def task_proof(before,out):
    contract=n/'vz-skylight-consumer-contract-v1/build-v3/contract.json';j=json.loads(contract.read_bytes())
    assert p.pin(contract)['sha256']=='f1fcabba053f2e1331b8750883170b939fed06dc5c026cd9393abfe7d134d86d'
    old=next(row for row in j['originalBoundedConsumerHelperBodies']if row['functionStart']==0x2260b7358);assert old['bytes']==TASK_LEN
    routes={q.stub_for(before,ix)['PC']:ix for ix in SELECTED};parsed=p.vz_reader.parse(before)
    text=next(sec for seg in parsed['segments']for sec in seg['sections']if sec['name']=='__text');calls=[]
    for off in range(text['at'],text['at']+text['bytes'],4):
        word=struct.unpack_from('<I',before,off)[0]
        if word&0xfc000000 not in(0x14000000,0x94000000):continue
        target=q.branch_target(0x100000000+off,word)
        if target in routes:calls.append(dict(fileoff=off,index=routes[target],branchWord=word,stub=target))
    assert len(calls)==2 and all(TASK<=row['fileoff']<TASK+TASK_LEN for row in calls)
    assert [row['index']for row in calls]==[315,312]
    status_call,pattern_call=calls;assert pattern_call['fileoff']-status_call['fileoff']==16
    assert struct.unpack_from('<3I',before,status_call['fileoff']+4)==(0xd2800001,0xaa1703e2,0xd2800003)
    assert struct.unpack_from('<2I',before,status_call['fileoff']-4)[0]==0xb9801697
    # No branch or load consumes x0 between the status and refusal function:
    # x0 is passed unchanged while the task sets x1=0,x2=signed pattern,x3=0.
    # Pattern result is immediately replaced by the original retained x22,
    # then the original release/deletion cleanup. No success test exists.
    assert struct.unpack_from('<I',before,pattern_call['fileoff']+4)[0]==0xaa1603e0
    with p.CACHE.open('rb')as stream:
        cache=p.DyldContext(stream);assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc';subs=cache.addSubCaches(p.CACHE)
        try:
            offset,owner=cache.convertAddr(old['functionStart']);body=owner.getBytes(offset,TASK_LEN)
            file=out/'original-haptic-task-complete.bin';file.write_bytes(body);assert p.pin(file)['sha256']==old['sha256']
        finally:
            for sub in subs:sub.close()
    return dict(originalContract=p.pin(contract),originalCompleteTask=p.pin(file),currentWholeTask=p.pin_bytes(before[TASK:TASK+TASK_LEN])if hasattr(p,'pin_bytes')else dict(bytes=TASK_LEN,hex=before[TASK:TASK+TASK_LEN].hex()),
       originalTaskLC26Start=old['functionStart'],originalTaskLC26End=old['functionEnd'],onlyTwoAffectedDirectCallers=calls,
       sourceStatusIsErrorNotConnectionID=True,statusForwardedOnlyToNewRefusalContract=True,patternReturnIgnoredAndCleanupPreserved=True,
       originalTaskExecuted=False)

def main():
    out=n/'vz-own-uikit-haptic-source-port-data-v2';assert not out.exists();out.mkdir(mode=0o700)
    previous=n/'vz-own-uikit-event-init-source-port-data-v2/candidate.json';j=json.loads(previous.read_bytes());pins=[]
    for freeze in(previous.parent/'freeze.json',n/'uikit-input-current-definitions-readonly-v1/freeze.json'):
        for row in json.loads(freeze.read_bytes())['files']:
            assert p.pin(Path(row['path']))==row;pins.append(row)
        pins.append(p.pin(freeze))
    base=j['frontendCandidate'];assert p.pin(Path(base['path']))==base;before=Path(base['path']).read_bytes()
    proof=task_proof(before,out);p.save(out/'original-task-proof.json',proof)
    paths=[p.ROOT/'VirtualMac/vz/host'/name for name in('vm27_no_mac_haptic_port_v1.h','vm27_no_mac_haptic_port_v1.c','test-vm27-no-mac-haptic-port-v1.c','vm27_frontend_owned_xpc_aggregate_v1.c')]
    sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip();runs=[]
    def run(label,args):
        args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
        runs.append(dict(label=label,argv=args,exit=r.returncode));p.save(out/'processes.json',runs)
        assert r.returncode==0,(label,r.stderr.decode());return r
    for mode,flags in(('normal',[]),('san',['-fsanitize=address,undefined'])):
        exe=out/('fixture-mac-'+mode);run('build-'+mode,['xcrun','clang','-O2','-Wall','-Wextra','-Werror',*flags,paths[1],paths[2],'-o',exe])
        result=json.loads(run('run-'+mode,[exe]).stdout);assert result==dict(checks=454,failures=0,unsupportedStatusRequests=64,unsupportedPatterns=64,hardwareCalls=0,VZCalls=0)
    directory=out/'private';directory.mkdir();copies=[]
    for source in sorted((previous.parent/'private').iterdir()):
        if source.name=='XF':continue
        dest=directory/source.name;dest.write_bytes(source.read_bytes());copies.append(dict(source=p.pin(source),candidate=p.pin(dest),wholeBytesIdentical=True))
    provider=directory/'VM27NoMacHapticPort.dylib';flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-Wall','-Wextra','-Werror']
    run('build-ios-provider',flags+['-dynamiclib',paths[1],'-Wl,-install_name,@rpath/VM27NoMacHapticPort.dylib','-Wl,-no_adhoc_codesign','-o',provider])
    aggregate=directory/'XF';link=flags+['-dynamiclib','-nostdlib',paths[3],'-Wl,-install_name,@loader_path/XF','-Wl,-rpath,@loader_path']
    for name in('VM27VMNetUnavailable.dylib','VM27OriginalV10Transport.dylib','VM27NoMacCursorPort.dylib','VM27NoMacEventInitPort.dylib','VM27NoMacHapticPort.dylib'):link.append('-Wl,-reexport_library,'+str(directory/name))
    run('build-ios-aggregate',link+['-Wl,-no_adhoc_codesign','-o',aggregate])
    graph={'@loader_path/'+file.name:f.image(p.pin(file),'@loader_path/'+file.name)for file in directory.iterdir()};agg=graph['@loader_path/XF']
    assert not agg['exports']and len(agg['dependencies'])==5 and all(row['command']==0x8000001f for row in agg['dependencies'])
    portimage=graph['@loader_path/VM27NoMacHapticPort.dylib'];assert set(portimage['exports'])=={'_VM27NoHapticV1','_VM27RejectHapticV1','_VM27CopyHapticRejectV1'}
    retained=[]
    for old in j['previousTwentyFiveReexportDefinitionsPreserved']+[dict(name='_VM27NoMacEventV1')]:
        symbol=old['name'];found=f.resolve(graph,'@loader_path/XF',symbol,agg);assert found['status']=='actualDirectExport';retained.append(dict(name=symbol,proof=found))
    newdefs=[]
    for symbol in sorted(portimage['exports']):
        found=f.resolve(graph,'@loader_path/XF',symbol,agg);assert found['status']=='actualDirectExport';newdefs.append(dict(name=symbol,proof=found))
    native=s.primary.captured_images()
    for group in('system','stock-extra','cxx-leaf'):s.join_capture(native,group,n/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in('dyld-leaf','xpc-leaf'):s.join_capture(native,group,n/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    f.join_kernel(s,native)
    for fn in(f.join_hid_extra,f.join_swift_two,f.join_eight,f.join_three,f.join_trace,f.join_unwind,f.join_compiler,f.join_crypto):fn(s,native)
    assert len(native)==36;raw=provider.read_bytes();deps={row['ordinal']:row['path']for row in p.dependencies(raw)};native_defs=[]
    for row in q.import_records(raw,p.commands)['imports']:
        assert row['ordinal']>0 and not row['weak'];found=s.primary.resolve(native,deps[row['ordinal']],row['name']);assert found['status']=='actualDirectExport';native_defs.append(dict(row,owner=deps[row['ordinal']],definition=found))
    after=transform(before);verification=validate(before,after);candidate=out/'VZ27.own-uikit-no-mac-haptic.mac.inert.macho-data';candidate.write_bytes(after);candidate.chmod(0o600)
    negatives=[]
    for label,off in(('changed original task cleanup',TASK+160),('changed genuine sender',0x5c770),('changed retained consumed-init port',0x649e4),('changed metadata',0x2f0600),
                      ('changed haptic PAC wholeword',q.stub_for(before,312)['chain']['at']+7),('wrong new haptic ordinal',q.import_records(after,p.commands)['imports'][315]['command']),('wrong new error name',q.strings(before)[312][0])):
        damaged=bytearray(after);damaged[off]^=1
        try:validate(before,bytes(damaged))
        except(AssertionError,ValueError):negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('damaged haptic source port accepted')
    for label,op in(('missing real refusal provider',lambda g:g.pop('@loader_path/VM27NoMacHapticPort.dylib')),('ordinary load cannot reexport refusal contract',lambda g:g['@loader_path/XF']['dependencies'][4].update(command=12))):
        damaged=copy.deepcopy(graph);op(damaged);assert f.resolve(damaged,'@loader_path/XF','_VM27NoHapticV1',damaged['@loader_path/XF'])['status']!='actualDirectExport';negatives.append(dict(name=label,rejected=True))
    for file in(candidate,provider,aggregate):run('validate-'+file.name,['xcrun','dyld_info','-validate_only',file])
    p.save(out/'candidate.json',dict(schema='Independent own UIKit explicit ENOTSUP haptic task source port v1',sourceFrontend=base,frontendCandidate=p.pin(candidate),frontendAggregate=p.pin(aggregate),
        hapticCapabilityProvider=p.pin(provider),sourceFiles=[p.pin(file)for file in paths],wholeCopiedPreviousProviders=copies,
        originalTaskProof=p.pin(out/'original-task-proof.json'),verification=verification,previousTwentySixReexportDefinitionsPreserved=retained,
        explicitHapticDefinitions=newdefs,providerCurrentStrongImports=native_defs,negativeControls=negatives,
        errorStatusNeverRepresentsConnectionID=True,hapticErrorsNotSuccessfulActuation=True,noSLSOrCGSExportsProvided=True,
        originalMacArtifactPreserved=True,originalVZSenderFramesAndVMExecutorPreserved=True,ownedUIKitInputAndSixParameterInitializerPreserved=True,
        originalHapticTaskExecuted=False,actualIOSHapticProviderExecuted=False,originalVZLoaded=False,completeCurrentStrongLoadGraph=False,
        parentFactoryIntegration=False,providerSigningCalls=0,deviceOperations=0,nativeCPUCalls=0,guestInstructions=0,full27Backend=False))
    pins += [p.pin(Path(__file__))]+[p.pin(file)for file in paths]+[p.pin(file)for file in out.rglob('*')if file.is_file()]
    pins += [p.pin(file)for file in (n/'vz-own-uikit-haptic-source-port-data-v1-failed').rglob('*')if file.is_file()]
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),verification=verification,provider=p.pin(provider),currentStrongImports=len(native_defs))))
if __name__=='__main__':
    try:main()
    except Exception as exc:
        out=n/'vz-own-uikit-haptic-source-port-data-v2'
        if out.exists():p.save(out/'failure.json',dict(error=repr(exc),candidateWritten=(out/'candidate.json').exists(),deviceOperations=0));(out/'failed-builder.py').write_bytes(Path(__file__).read_bytes())
        raise
