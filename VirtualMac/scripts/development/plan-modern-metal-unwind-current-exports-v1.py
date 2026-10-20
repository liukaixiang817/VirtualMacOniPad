#!/usr/bin/env python3
"""Derive the native libunwind export request from the actual captured prefix."""
import importlib.util,json,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('unwind_stock',HERE/'audit-modern-current-stock-extra-exports-v2.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s);p=s.p
from current_hid_extra_three_capture_v1 import commands,mapping

def main():
    n=p.NODE;out=n/'ipad-current-metal-unwind-exports-plan-v1';assert not out.exists()
    combined=n/'ipad-current-trace-unwind-original-cn-read-plan-v1';cap=n/'ipad-current-trace-unwind-original-cn-readonly-v1'
    original=n/'ipad-current-metal-unwind-command-prefix-plan-v1'
    derivation=json.loads((original/'derivation.json').read_bytes());hp=Path(derivation['currentHeaders']['path']);headers=json.loads(hp.read_bytes())
    pins=[]
    for pd in (combined,original):
        for pin in json.loads((pd/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path']))==pin;pins.append(pin)
        pins.append(p.pin(pd/'freeze.json'))
    receipt=s.checked_capture(cap,combined/'request.json',hp)
    assert receipt['requestedBytes']==7587 and receipt['requestedRanges']==3
    assert receipt['readerSHA256']==derivation['reader']['sha256']
    captured=next(x for x in receipt['ranges']if x['name']=='metal-unwind-commands-prefix')
    assert {k:captured[k]for k in ('cache','offset','length')}=={k:derivation['request'][k]for k in ('cache','offset','length')}
    prefix=Path(captured['path']);raw=prefix.read_bytes();extent=32+struct.unpack_from('<I',raw,20)[0]
    assert 32<extent<=4096;complete=raw[:extent];parsed=commands(p,complete,derivation['actualImage'])
    assert parsed['UUID']=='41f6058d8f923691ad00f37a64a36be4'
    request=dict(name='metal-unwind-exports',**mapping(headers,parsed['exportVA'],parsed['exportLength']))
    assert request['cache']=='44-linkedit' and 0<request['length']<=2*1024*1024
    out.mkdir(mode=0o700);cp=out/'metal-unwind-commands.bin';cp.write_bytes(complete)
    p.save(out/'request.json',dict(ranges=[request]))
    p.save(out/'derivation.json',dict(schema='Actual libunwind full command-derived export request v1',
        currentHeaders=p.pin(hp),originalPrefixPlan=p.pin(original/'derivation.json'),actualCombinedPlan=p.pin(combined/'request.json'),
        actualCombinedReceipt=p.pin(cap/'receipt.json'),actualImage=derivation['actualImage'],actualPrefix=p.pin(prefix),
        completeActualCommands=p.pin(cp),actualLibSystemReexport=derivation['actualLibSystemReexport'],actualDependencies=parsed['dependencies'],
        actualExportVA=parsed['exportVA'],actualExportOffset=parsed['exportOffset'],actualExportLength=parsed['exportLength'],
        request=request,requestedRanges=1,requestedBytes=request['length'],actualExportsNotYetCaptured=True,
        actualUnwindDefinitionNotYetProven=True,deviceOperations=0,nativeCPUCalls=0,frameworkLoads=0,full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(x)for x in [Path(__file__),hp,prefix,cp,out/'request.json',out/'derivation.json',out/'source.py']+
        [cap/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py')]+[Path(x['path'])for x in receipt['ranges']]]
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),freeze=p.pin(out/'freeze.json'),range=request,fullCommandBytes=extent)))

if __name__=='__main__':main()
