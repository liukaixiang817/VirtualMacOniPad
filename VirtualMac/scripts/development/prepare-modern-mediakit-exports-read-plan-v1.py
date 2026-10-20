#!/usr/bin/env python3
"""Derive MediaKit trie ranges exclusively from guarded current commands."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('mediakit_current_s',HERE/'audit-modern-current-stock-extra-exports-v2.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s);p,n=s.p,s.p.NODE
from current_hid_extra_three_capture_v1 import commands,inventory,mapping

def main():
    out=n/'ipad-current-mediakit-exports-plan-v1';assert not out.exists()
    heads=n/'ipad-current-mediakit-member31-header-readonly-v1/headers.json'
    headers=json.loads(heads.read_bytes());assert len(headers['headers'])==18
    plan=n/'ipad-current-mediakit-current-prefix-plan-v1'
    cap=n/'ipad-current-mediakit-command-prefix-readonly-v1'
    pins=[]
    for row in json.loads((plan/'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path']))==row;pins.append(row)
    receipt=s.checked_capture(cap,plan/'request.json',heads)
    assert receipt['readerSHA256']==p.pin(cap/'reader-source.py')['sha256']=='742595c2ecd4bf119ba454c17a3e135c7ea4e546336f675dc1eccf32534ddfef'
    assert receipt['requestedRanges']==1 and receipt['requestedBytes']==4096
    assert (cap/'manifest.json').read_bytes()==(plan/'request.json').read_bytes()
    archive=n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail=n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    rows=inventory(archive.read_bytes()[:4096],tail.read_bytes(),headers)
    expected=next(row for row in rows if row['path']=='/System/Library/PrivateFrameworks/MediaKit.framework/MediaKit')
    assert expected['UUID']=='bb1e22a209273ee8a614cc87ff8f34c3'
    prefix=cap/'mediakit-command-prefix.bin';raw=prefix.read_bytes();assert len(raw)==4096
    length=32+struct.unpack_from('<I',raw,20)[0];assert 32<length<=len(raw)
    complete=raw[:length];parsed=commands(p,complete,expected)
    assert mapping(headers,expected['address'],4096)=={k:receipt['ranges'][0][k]for k in ('cache','offset','length')}
    request=dict(name='mediakit-exports',**mapping(headers,parsed['exportVA'],parsed['exportLength']))
    assert request['cache']=='44-linkedit' and request['length']<=2*1024*1024
    out.mkdir(mode=0o700);(out/'mediakit-complete-commands.bin').write_bytes(complete)
    p.save(out/'request.json',dict(ranges=[request]))
    p.save(out/'derivation.json',dict(schema='Actual current MediaKit complete commands to export trie request v1',headers=p.pin(heads),
        actualInventoryImage=expected,actualPrefix=p.pin(prefix),actualPrefixReceipt=p.pin(cap/'receipt.json'),
        completeCommands=p.pin(out/'mediakit-complete-commands.bin'),parsedActualCommands=parsed,exportRequest=request,
        exactLCExportOffsetToLinkeditVAToCurrentMapping=True,currentExportsCaptured=False,
        currentDefinitionsValidated=False,providerLoaded=False,deviceOperations=0,nativeCPUCalls=0,full27Backend=False))
    pins += [p.pin(x)for x in (Path(__file__),heads,archive,tail,plan/'freeze.json')]
    pins += [p.pin(file)for file in cap.iterdir()if file.is_file()]
    pins += [p.pin(file)for file in out.iterdir()if file.is_file()]
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),range=request,completeCommandBytes=length,freeze=p.pin(out/'freeze.json'))))
if __name__=='__main__':main()
