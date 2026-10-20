#!/usr/bin/env python3
"""Read-only finite peer of Runtime8's two changed signed images and actual seals."""
import argparse, hashlib, importlib.util, json, pathlib, plistlib, re, stat, struct, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = R / 'VirtualMac/scripts/development'
CHILD = 'com.apple.Virtualization.VirtualMachine'
PREMAIN = 'VM27OwnedAppChildPreMainV3.dylib'
OWN = '_VM27OwnedPlatformLaunchPrepareV1'
PROFILE = 'Resources/' + CHILD + '.sb'
def need(v, reason):
    if not v: raise ValueError(reason)
def pin(p):
    p=pathlib.Path(p).resolve();raw=p.read_bytes()
    return dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def load_module(name,p):
    spec=importlib.util.spec_from_file_location(name,p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def rows(p):
    v=json.loads(pathlib.Path(p).read_bytes());return {r['path']:{k:r[k] for k in ('path','bytes','sha256')} for r in v['files']}
def actual(row,frozen):
    need(frozen.get(row['path'])==row and pin(row['path'])==row,'actual frozen pin '+row['path'])
def blobs(raw,image):
    c=next(c for c in image.commands if c['cmd']==0x1d)
    off,size=struct.unpack_from('<II',raw,c['at']+8);body=raw[off:off+size]
    magic,total,count=struct.unpack_from('>III',body);need(magic==0xfade0cc0 and total<=size,'actual signature')
    result={}
    for i in range(count):
        slot,at=struct.unpack_from('>II',body,12+8*i);length=struct.unpack_from('>I',body,at+4)[0]
        need(at>=12+8*count and length>=8 and at+length<=total and slot not in result,'actual slot range')
        result[slot]=body[at:at+length]
    return result

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--candidate',required=True,type=pathlib.Path)
    ap.add_argument('--output',required=True,type=pathlib.Path);args=ap.parse_args()
    output=args.output.resolve();need(output.parent==N and not output.exists(),'fresh finite review output')
    frozen_path=args.candidate.parent/'freeze.json';frozen=rows(frozen_path)
    actual(pin(args.candidate),frozen);c=json.loads(args.candidate.read_bytes())
    need(c['files']==149 and c['localCodeSigned'] is True and c['sandboxProfileApplied'] is False and
         c['sandboxApplied'] is False and c['nativeSandboxApplyUnavailable']==45,'actual149, owned preparation not applied sandbox')
    actual(c['manifest'],frozen);raw=pathlib.Path(c['manifest']['path']).read_bytes();manifest=plistlib.loads(raw)
    actual(c['anchorSource'],frozen);actual(c['anchorIOSObject'],frozen)
    anchor=pathlib.Path(c['anchorSource']['path']).read_text();match=re.search(r'SHA256V1\[32\]=\{([^}]+)\}',anchor)
    need(match and bytes(int(x)for x in match[1].split(','))==hashlib.sha256(raw).digest() and
         'ManifestBytesV1='+str(len(raw))+';' in anchor,'actual final manifest digest/byte length anchor')
    new={r['id']:r for r in manifest['files']};need(len(new)==len(manifest['files'])==149,'unique actual149 rows')
    base_path=N/'independent27-signed-runtime-product-v6-attempt1/candidate.json';base=json.loads(base_path.read_bytes())
    bf=rows(base_path.parent/'freeze.json');actual(pin(base_path),bf);actual(base['manifest'],bf)
    old_manifest=plistlib.loads(pathlib.Path(base['manifest']['path']).read_bytes());old={r['id']:r for r in old_manifest['files']}
    need(len(old)==148 and set(new)==set(old)|{'child-sandbox-profile'},'actual baseline148 and only Main resource added')
    old_root=pathlib.Path(base['runtimeRoot']);root=pathlib.Path(c['runtimeRoot'])
    child_id=manifest['childEntryContract']['childID'];premain_id='child:'+PREMAIN
    changed={child_id,premain_id,'child-coderesources','dependency-proof'};unchanged=[]
    need(sum(r['kind']=='mach-o'for r in new.values())==139 and len({r['cdhash']for r in new.values()if r['kind']=='mach-o'})==139,'actual139 distinct signed identities')
    for identity,row in new.items():
        rel=pathlib.PurePosixPath(row['path']);need(not rel.is_absolute() and all(s not in ('','..','.')for s in rel.parts),'regular relative path')
        path=root.joinpath(*rel.parts);need(stat.S_ISREG(path.lstat().st_mode),'new regular file')
        got=pin(path);actual(got,frozen);need(got['bytes']==row['bytes'] and got['sha256']==row['sha256'],'new manifest/file join')
        if identity in old:
            before=pin(old_root/old[identity]['path']);actual(before,bf)
            need(before['bytes']==old[identity]['bytes'] and before['sha256']==old[identity]['sha256'],'old actual manifest/file join')
            if identity not in changed:
                need(old[identity]==row and before['bytes']==got['bytes'] and before['sha256']==got['sha256'],'unchanged wholebytes '+identity)
                unchanged.append(dict(id=identity,file=got,signed=row['kind']=='mach-o'))
            else:
                need(before['sha256']!=got['sha256'] and old[identity]['path']==row['path'] and
                     old[identity]['kind']==row['kind'] and old[identity]['role']==row['role'],'intended actual delta')
    need(sum(r['signed']for r in unchanged)==137,'only two changed signed images;137 unchanged wholebytes')
    actual_paths={str(p.relative_to(root))for p in root.rglob('*')if p.is_file()}
    need(actual_paths=={r['path']for r in new.values()}|{'VM27IndependentRuntimeManifestV1.plist'},'no undeclared packaged file')
    need(not any(p.is_symlink()for p in root.rglob('*')),'no packaged symlink')
    reader_path=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    reader=load_module('runtime8_peer_macho',reader_path)
    sig_path=B/'review-independent27-signed-runtime-product-v2.py'
    sig=load_module('runtime8_peer_signed',sig_path)
    stage_pin=json.loads(pathlib.Path(c['admission']['path']).read_bytes())['actualStage'];actual(stage_pin,frozen)
    stage=json.loads(pathlib.Path(stage_pin['path']).read_bytes());stage_rows={r['key']:r['staged']for r in stage['stagedImages']}
    signatures=[];images={}
    for identity,key in [(child_id,CHILD),(premain_id,PREMAIN)]:
        path=root/new[identity]['path'];external={int(slot):(root/new[resource]['path']).read_bytes()for slot,resource in new[identity].get('signatureSlots',{}).items()}
        signatures.append(sig.signed_image(path,new[identity],external))
        after=path.read_bytes();image=reader.MachO(after);images[key]=image
        actual(stage_rows[key],frozen);source=pathlib.Path(stage_rows[key]['path']).read_bytes();before=reader.MachO(source)
        need(image.uuid==before.uuid and image.sections==before.sections and image.imports==before.imports and
             image.binds==before.binds and image.loads==before.loads and image.exports==before.exports,'actual signing preserves staged semantics/PAC')
        for section in before.sections:
            at,length=section['fileoff'],section['size']
            if at and length and section['flags']&255 not in (1,12,18):
                need(source[at:at+length]==after[at:at+length],'all staged backed sections unchanged by signing')
    child=images[CHILD];need(child.uuid=='4a6a588d1afd30f5a64d6304eb79be0b','genuine child UUID')
    need(child.imports[428]['name']==OWN and child.imports[428]['ordinal']==55 and child.imports[428]['weak']==0,
         'actual child428 explicitly binds owned preparation')
    dep=next(row for row in child.loads if row['ordinal']==55)
    need(dep['cmd']==12 and dep['path']=='@loader_path/'+PREMAIN,'existing required premain55')
    need(images[PREMAIN].exports[OWN]['flags']==0,'real own preparation export')
    original_child=reader.MachO((old_root/old[child_id]['path']).read_bytes())
    need(child.loads==original_child.loads and child.sections==original_child.sections and child.exports==original_child.exports,
         'original Main full loads/sections/exports retained')
    for a,b in zip(original_child.imports,child.imports):
        expected=dict(a,at=b['at'])
        if a['index']==428:expected.update(name=OWN,ordinal=55)
        need(expected==b,'only selected import semantics')
    need(len(original_child.imports)==len(child.imports) and child.binds==[dict(r,name=OWN if r['index']==428 else r['name'])for r in original_child.binds],
         'raw bind words/auth/key/slot/diversity preserve exact original values')
    before_child=original_child.data;after_child=child.data
    old_blobs=blobs(before_child,original_child);new_blobs=blobs(after_child,child)
    need(all(old_blobs[k]==new_blobs[k]for k in (2,5,7)),'original requirements/XML/DER wholebytes unchanged')
    entitlements=signatures[0]['embeddedEntitlements']
    need(entitlements==plistlib.loads(old_blobs[5][8:]) and len(entitlements)==13 and
         entitlements['com.apple.private.virtualization.plugin'] is True,'genuine unchanged thirteen entitlements')
    need({s['slot']for s in signatures[0]['actualSpecialSlots']if s['external']}=={1,3},'real Info1/resources3 slots')
    need(signatures[1]['embeddedEntitlements'] is None,'no new premain grant')
    old_seal=plistlib.loads((old_root/old['child-coderesources']['path']).read_bytes());new_seal=plistlib.loads((root/new['child-coderesources']['path']).read_bytes())
    pcd=new[premain_id]['cdhash'];nested='MacOS/'+PREMAIN
    need(new_seal['files2'][nested]=={'cdhash':bytes.fromhex(pcd),'requirement':'cdhash H"'+pcd+'"'},'true new premain nested seal')
    need(new_seal['files2'][PROFILE]=={'hash2':bytes.fromhex('59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504')},'genuine Main profile mandatory seal')
    stripped=dict(new_seal)
    for bank in ('files','files2'):
        stripped[bank]=dict(new_seal.get(bank,{}));stripped[bank].pop(PROFILE,None)
    stripped['files2'][nested]=old_seal['files2'][nested]
    need(stripped==old_seal,'only new Main resource and changed premain record in CodeResources')
    for key in old_manifest:
        if key!='files':need(manifest[key]==old_manifest[key],'all entry/role/load contracts retained')
    output.mkdir(mode=0o700)
    report=dict(schema='Independent Runtime8 finite actual signed delta peer v1',candidate=pin(args.candidate),inputFreeze=pin(frozen_path),
        baselineCandidate=pin(base_path),baselineFreeze=pin(base_path.parent/'freeze.json'),actualManifest=c['manifest'],
        actualAnchor=c['anchorSource'],actualAnchorIOSObject=c['anchorIOSObject'],actualStage=stage_pin,
        actualSignedImages=139,actualRows=149,changedSignedImages=signatures,actualChangedPrimaryPagesVerified=sum(s['actualCodePages']for s in signatures),
        actualTwoChangedImagesAllPagesAndSpecialSlotsVerified=True,unchangedSignedWholebytes=137,unchangedFiles=unchanged,
        originalChildXMLDERRequirementsWholebytesRetained=True,originalPACAndBackedSectionsWholebytesRetained=True,
        onlyExistingRequiredChild55OwnedAPI428=True,onlyMainProfileAndNewPremainResourceSealChanged=True,
        unchangedImagesPrimaryPagesReverified=False,ownPlatformPrepContract=c['ownPlatformPrepContract'],
        nativeSandboxApplyUnavailable=45,sandboxApplied=False,sandboxProfileApplied=False,
        sandboxInitSuccessFabricated=False,ownedPlatformPreparationActuallyExecuted=False,
        findings=[],finiteLocalScopePassed=True,deviceOperations=0,trustCacheOperations=0,guestBoot=False)
    (output/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    (output/'freeze.json').write_text(json.dumps(dict(files=[pin(__file__),pin(sig_path),pin(reader_path),pin(output/'review.json'),
        pin(args.candidate),pin(frozen_path),pin(base_path),pin(base_path.parent/'freeze.json'),c['manifest'],c['anchorSource'],c['anchorIOSObject'],stage_pin,
        stage_rows[CHILD],stage_rows[PREMAIN]]),indent=2)+'\n')
    print(json.dumps(dict(review=pin(output/'review.json'),freeze=pin(output/'freeze.json'),changedPages=report['actualChangedPrimaryPagesVerified'],findings=[])))
if __name__=='__main__':main()
