#!/usr/bin/env python3
"""Actual current Core exact names only; no process-wide absence inference."""
from pathlib import Path
import argparse, ast, base64, hashlib, json, struct
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
checks=0;pins={}
def check(v,w):
    global checks
    checks+=1
    if not v:raise ValueError(w)
def pin(p):
    p=Path(p);b=p.read_bytes();r=dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest());pins[str(p)]=r;return r
def read(p):pin(p);return Path(p).read_bytes()
def exact(row):
    b=read(row['path']);check(len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256'],'actual pin');return b
def absent(table):
    names=['_$ss20__StaticArrayStorageCN','_$ss20__StaticArrayStorageCMn','_$ss20__StaticArrayStorageCMa','_OBJC_CLASS_$_TtCs20__StaticArrayStorage','_OBJC_METACLASS_$_TtCs20__StaticArrayStorage']
    check(all(n not in table for n in names),'five actual exact exported names absent');return names
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();D=a.output.resolve();check(not D.exists(),'new evidence directory');D.mkdir()
    parser=N/'static-cn-old-n2-own-ios-fixture-local-v4/audit.py';tree=ast.parse(read(parser));selected=[x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name in ['capture','trie','header']];check(len(selected)==3,'three byte parser functions only')
    namespace=dict(Path=Path,N=N,R=R,struct=struct,json=json,hashlib=hashlib,base64=base64,read=read,exact=exact,check=check)
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(parser),'exec'),namespace)
    images=json.loads(read(N/'universalhid-current-stock-extra-exports-audit-v4/audit.json'))['images'];core=next(x for x in images if x['path']=='/usr/lib/swift/libswiftCore.dylib')
    header=namespace['capture'](core['header']);table=namespace['trie'](namespace['capture'](core['trie']));uuid,_=namespace['header'](header);check(uuid=='f896d145e02539d6afd3bc0a2ad4f839','actual current old Core UUID');names=absent(table)
    section=None;at=32
    for _ in range(struct.unpack_from('<I',header,16)[0]):
        cmd,size=struct.unpack_from('<II',header,at)
        if cmd==0x19:
            for i in range(struct.unpack_from('<I',header,at+64)[0]):
                p=at+72+i*80
                if header[p:p+16].split(b'\0')[0]==b'__objc_classname':section=struct.unpack_from('<QQI',header,p+32)
        at+=size
    check(section==(6460527272,299,17715880),'actual complete native __objc_classname coordinates')
    capture=N/'ipad-current-trace-unwind-original-cn-readonly-v1';receipt=json.loads(read(capture/'receipt.json'));row=next(x for x in receipt['ranges'] if x['name']=='swiftcore-original-cn-objc-classnames-complete')
    check((row['cache'],row['offset'],row['length'])==('01',17715880,299),'actual selected range matches native section')
    raw=namespace['capture'](dict(path=row['path'],bytes=row['length'],sha256=row['sha256']))
    check(raw.endswith(b'\0') and len(raw)==299,'whole fourteen native CStrings');actual=raw[:-1].split(b'\0');check(len(actual)==14 and all(actual),'fourteen nonempty CStrings')
    check(b'_TtCs20__StaticArrayStorage' not in actual and b'__StaticArrayStorage' not in actual,'exact names absent only within this captured section')
    prior=N/'static-cn-original-name-current-contract-local-v1/request.json';request=json.loads(read(prior));check(request['ranges']==[{k:row[k] for k in ['name','cache','offset','length']}],'unmodified original bounded request')
    negatives=[]
    for n in names:
        bad=dict(table);bad[n]=(0,1,None)
        try:absent(bad)
        except ValueError:negatives.append('present-export-'+n)
        else:raise ValueError('present name accepted')
    # Capture receipt parser separately validates manifest/script/raw base64
    # and all current headers; this section lacks generated Swift class names.
    output=dict(schema='Actual current Core original CN exact name finite boundary v2',source=pin(Path(__file__)),checks=checks,currentCoreUUID=uuid,actualCompleteNativeExports=len(table),actualFiveExactExportNamesAbsent=names,actualCompleteClassnameBytes=299,actualClassnameCStrings=[x.decode() for x in actual],actualRequestedCoordinates=row,originalRequest=pin(prior),negativeCases=negatives,currentLiteralCoreClassnameSectionOriginalNameAbsent=True,nativeGeneratedSwiftClassNamesComplete=False,currentAllCoreTypeDescriptorsRead=False,fullProcessPriorObjCNameAbsenceProven=False,preMainRegistrationMayCollide=True,plannedSameNameMustEqualExactLinkedCNAndCMnOwner=True,originalCNRuntimeIdentity=False,originalFullAppleGraph=False,deviceOperations=0,nativeCPUCalls=0,nativeVMCalls=0,full27Backend=False,inputs=sorted(pins.values(),key=lambda r:r['path']))
    (D/'audit.json').write_text(json.dumps(output,indent=2)+'\n');print(json.dumps(dict(checks=checks,strings=len(actual),processAbsenceProven=False)))
if __name__=='__main__':main()
