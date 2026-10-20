#!/usr/bin/env python3
"""Pin two unchanged real array providers to native captured export contracts."""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('actual',HERE/'audit-modern-universalhid-current-stock-exports-v1.py')
actual=importlib.util.module_from_spec(spec);spec.loader.exec_module(actual)
p=actual.p;NODE=p.NODE;HIST=p.ROOT/'DeviceDiagnostics/2026-10-02-macos27-backend'
RESERVE=NODE/'vmm-contiguousarray-reserve-contract-v1/build-v6/candidate.json'
SYSTEM_HEADERS=NODE/'ipad-current-cache-system-headers-v1/headers.json'
SYSTEM_COMMANDS=NODE/'ipad-current-cache-system-commands-readonly-v1'
SYSTEM_EXPORTS=NODE/'ipad-current-cache-system-exports-readonly-v1'
SYSTEM_MANIFEST=NODE/'ipad-current-cache-system-exports-manifest-v1.json'


def checked_current25(header,receiptpath):
    folder=receiptpath.parent;receipt=json.loads(receiptpath.read_text());heads=json.loads((folder/'headers.json').read_text())
    assert receipt['transportExit']==0 and receipt['requestedDataBytes']==8192
    assert heads['mainUUID']=='1995ea169d0a33a0b78962cf99891168'
    assert not any(receipt[k]for k in('deviceWrites','nativeCPUCalls','newFrameworksLoaded'))
    assert not heads['exportsVerifiedByHeaderAlone']
    for name,key in [('script.sh','scriptSHA256'),('stdout','stdoutSHA256'),('stderr','stderrSHA256')]:
        assert p.pin(folder/name)['sha256']==receipt[key]
    script=(folder/'script.sh').read_text();stdout=(folder/'stdout').read_bytes()
    assert script.count('= 307a229e3e3a2157562d3fe04a2955d898cdaa74dbb4ecfb0e59687fcfd06992 ]')==2
    assert stdout.endswith(b'FINAL_MAIN_CACHE_HEADER_MATCH\n') and len(heads['headers'])==2
    for row in heads['headers']:
        name=row['name'];path=folder/(name+'.header.bin')
        matches=re.findall(rb'BEGIN_BASE64 '+name.encode()+rb'\n([A-Za-z0-9+/=\n]+)\nEND_BASE64 '+name.encode()+rb'\n',stdout)
        assert len(matches)==1
        raw=base64.b64decode(re.sub(rb'\s',b'',matches[0]),validate=True)
        assert len(raw)==4096 and path.read_bytes()==raw
        assert p.pin(path)['sha256']==row['sha256'] and raw[88:104].hex()==row['UUID']
    assert header==folder/'25.header.bin'


def archived_header_match(current25):
    headers=(HIST/'ipad-cache-headers.bin').read_bytes()
    current=json.loads((NODE/'ipad-current-cache-header-readonly-v2/headers.json').read_text())
    for row in current['headers']:
        matches=[headers[i:i+4096]for i in range(0,len(headers)-4095,4096)if headers[i+88:i+104].hex()==row['UUID']]
        assert len(matches)==1 and __import__('hashlib').sha256(matches[0]).hexdigest()==row['sha256']
    assert current25.read_bytes()==headers[25*4096:26*4096]
    assert current25.read_bytes()[88:104].hex()=='5f2cfcc69748304391af715094b65e8d'


def checked_system_receipt(folder,manifest):
    receipt=json.loads((folder/'receipt.json').read_text())
    assert receipt['mainCacheUUID']=='1995ea169d0a33a0b78962cf99891168'
    assert receipt['transportExit']==0 and receipt['allHeaderPinsMatchBeforeAndAfter']
    assert receipt['headersSHA256']==p.pin(SYSTEM_HEADERS)['sha256']and receipt['manifestSHA256']==p.pin(manifest)['sha256']
    assert not any(receipt[k]for k in('deviceWrites','nativeCPUCalls','newFrameworksLoaded'))
    for name,key in [('script.sh','scriptSHA256'),('stdout','stdoutSHA256'),('stderr','stderrSHA256')]:
        assert p.pin(folder/name)['sha256']==receipt[key]
    assert sum(r['length']for r in receipt['ranges'])==receipt['requestedBytes']
    for row in receipt['ranges']:
        path=Path(row['path']);assert path.parent==folder
        assert p.pin(path)['sha256']==row['sha256']and path.stat().st_size==row['length']
    return receipt


def current_system_images():
    heads=json.loads(SYSTEM_HEADERS.read_text());assert heads['mainUUID']=='1995ea169d0a33a0b78962cf99891168'
    for row in heads['inputHeaderRecords']+heads['inputCaptureReceipts']:assert p.pin(Path(row['path']))==row
    checked_system_receipt(SYSTEM_COMMANDS,NODE/'ipad-current-cache-system-commands-manifest-v1.json')
    checked_system_receipt(SYSTEM_EXPORTS,SYSTEM_MANIFEST)
    actualmaps={r['name']:r for r in heads['headers']};result={}
    manifest=json.loads(SYSTEM_MANIFEST.read_text())
    for row in manifest['mappedActualLoadCommands']:
        headerpath=Path(row['actualCommandPath']);header=headerpath.read_bytes();size=32+struct.unpack_from('<I',header,20)[0]
        assert size==len(header)and p.pin(headerpath)['sha256']==row['actualCommandSHA256']
        uuid=None;identity=None;export=None
        for cmd,at,length in p.commands(header):
            if cmd==27:uuid=header[at+8:at+24].hex()
            elif cmd==13:
                off=struct.unpack_from('<I',header,at+8)[0];identity=header[at+off:at+length].split(b'\0')[0].decode()
            elif cmd==0x80000033:export=struct.unpack_from('<II',header,at+8)
        assert identity==row['image']and uuid==row['imageUUID']
        if export is None:
            for cmd,at,length in p.commands(header):
                if cmd==0x80000022:export=struct.unpack_from('<II',header,at+40)
        assert export==(row['originalImageExportOffset'],row['length'])
        link=next(s for s in p.segments(header)if s['name']=='__LINKEDIT')
        va=link['address']+export[0]-link['fileoff'];assert va==row['exportVA']
        mapping=next(m for m in actualmaps['44-linkedit']['maps']if m['address']<=va and va+export[1]<=m['address']+m['size'])
        assert row['offset']==mapping['fileOffset']+va-mapping['address']and mapping==row['cacheMapping']
        blobpath=SYSTEM_EXPORTS/(row['name']+'.bin');blob=blobpath.read_bytes();assert len(blob)==export[1]
        exports=actual.trie(blob);dependencies=p.dependencies(header)
        assert all(not e['flags']&8 or 1<=e['ordinal']<=len(dependencies)for e in exports.values())
        result[identity]=dict(path=identity,UUID=uuid,headerSource=p.pin(headerpath),trieSource=p.pin(blobpath),
                             currentActualCommandsAndExports=True,exports=exports,dependencies=dependencies)
    assert len(result)==4
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--current-cache25-header',type=Path,required=True)
    ap.add_argument('--current-cache25-receipt',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    header=args.current_cache25_header.resolve();receiptpath=args.current_cache25_receipt.resolve()
    checked_current25(header,receiptpath);archived_header_match(header)
    images=actual.captured_images();current=current_system_images();images.update(current)
    candidate=json.loads(RESERVE.read_text());role=next(r for r in candidate['roles']if r['role']=='ios')
    providers=[]
    for name in('provider','unchangedSiblingProvider'):
        plan=role[name];path=Path(plan['path']);assert p.pin(path)=={k:plan[k]for k in('path','bytes','sha256')}
        b=path.read_bytes();deps={r['ordinal']:r['path']for r in p.dependencies(b)}
        imp=p.imports(b)['imports'];assert len(imp)==(10 if name=='provider'else 16)
        rows=[]
        for r in imp:
            assert r['ordinal']>0 and not r['weak'];proof=actual.resolve(images,deps[r['ordinal']],r['name'])
            assert proof['status']=='actualDirectExport',(r,proof)
            rows.append(dict(symbol=r['name'],ordinal=r['ordinal'],proof=proof))
        providers.append(dict(provider=p.pin(path),runtimeImports=rows,
            allDirectOrTrueNativeReexportsResolved=True,providerBytesUnchanged=True))
    report=dict(schema='Unchanged real array providers native dependencies pinned v1',
        currentCacheUUID='1995ea169d0a33a0b78962cf99891168',currentCache25Header=p.pin(header),currentCache25Receipt=p.pin(receiptpath),
        currentHeaders=p.pin(NODE/'ipad-current-cache-header-readonly-v2/headers.json'),currentPrimaryExportAudit=p.pin(NODE/'universalhid-current-stock-exports-audit-v2/audit.json'),
        currentSystemImageContracts=[{k:v for k,v in image.items()if k!='exports'}for image in current.values()],
        currentSystemCommandsAndExportsRecaptured=True,noArchivedExportEvidenceRequired=True,current25HeaderExactlyMatchesArchived=True,
        sourceArrayCandidate=p.pin(RESERVE),providers=providers,all26StrongProviderImportsResolved=True,
        nativeExecuted=False,deviceOperations=0,fullCurrentLoadGraphProven=False,full27Backend=False)
    p.save(out/'audit.json',report)
    files=[Path(__file__),HERE/'audit-modern-universalhid-current-stock-exports-v1.py',header,receiptpath,
        NODE/'ipad-current-cache-header-readonly-v2/headers.json',RESERVE,out/'audit.json']
    files += [HIST/'ipad-cache-headers.bin',SYSTEM_HEADERS,SYSTEM_MANIFEST,NODE/'ipad-current-cache-system-commands-manifest-v1.json']
    files += [receiptpath.parent/name for name in('headers.json','script.sh','stdout','stderr','main.header.bin')]
    files += [folder/name for folder in(SYSTEM_COMMANDS,SYSTEM_EXPORTS)for name in('receipt.json','script.sh','stdout','stderr')]
    files += [Path(image[k]['path'])for image in current.values()for k in('headerSource','trieSource')]
    files += [Path(row['provider']['path'])for row in providers]
    p.save(out/'freeze.json',dict(files=[p.pin(f)for f in files],nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),strongImports=26)))


if __name__=='__main__':main()
