#!/usr/bin/env python3
"""Derive trace export ranges from both captured complete command fragments."""
import importlib.util,json,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('trace_current_stock',HERE/'audit-modern-current-stock-extra-exports-v2.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s);p=s.p
from current_hid_extra_three_capture_v1 import commands,mapping

def main():
    n=p.NODE;out=n/'ipad-current-hid-trace-exports-plan-v1';assert not out.exists()
    hp=n/'ipad-current-cache-trace-header-readonly-v1/headers.json';headers=json.loads(hp.read_bytes())
    assert len(headers['headers'])==14
    pins=[]
    plans=['ipad-current-trace-metal-bounded-read-plan-v1','ipad-current-trace-exports-metal-default-body-plan-v2']
    caps=['ipad-current-trace-metal-bounded-readonly-v1','ipad-current-trace-tail-metal-default-body-readonly-v1']
    for plan,cap in zip(plans,caps):
        pd,cd=n/plan,n/cap
        for pin in json.loads((pd/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path']))==pin;pins.append(pin)
        receipt=s.checked_capture(cd,pd/'request.json',hp)
        assert receipt['readerSHA256']=='c6cea43fd413a7823ad7c38e7844617834bc1e1f399ef128637e3266cb4a4b7b'
        pins += [p.pin(x)for x in [pd/'freeze.json',pd/'request.json']+[cd/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py')]+[Path(x['path'])for x in receipt['ranges']]]
    derivation=json.loads((n/plans[1]/'derivation.json').read_bytes());image=derivation['actualTraceImage']
    prefix=n/caps[0]/'system-trace-commands-prefix.bin';tail=n/caps[1]/'system-trace-commands-tail.bin'
    raw=prefix.read_bytes()+tail.read_bytes();assert len(raw)==4848==32+struct.unpack_from('<I',raw,20)[0]
    parsed=commands(p,raw,image);assert parsed['UUID']=='cdca424284413402a6436a03c3eb9c15'
    assert mapping(headers,image['address'],4096)==dict(cache='09',offset=58937344,length=4096)
    row=dict(name='system-trace-exports',**mapping(headers,parsed['exportVA'],parsed['exportLength']))
    assert row['cache']=='44-linkedit' and row['offset']>=4096 and 0<row['length']<=2*1024*1024
    out.mkdir(mode=0o700);cp=out/'system-trace-commands.bin';cp.write_bytes(raw)
    p.save(out/'request.json',dict(ranges=[row]))
    p.save(out/'derivation.json',dict(schema='Genuine complete current trace command export request v1',
        currentHeaders=p.pin(hp),actualImage=image,completeActualCommands=p.pin(cp),actualDependencies=parsed['dependencies'],
        actualPrefix=p.pin(prefix),actualTail=p.pin(tail),actualExportVA=parsed['exportVA'],actualExportOffset=parsed['exportOffset'],
        actualExportLength=parsed['exportLength'],request=row,requestedRanges=1,requestedBytes=row['length'],
        actualTraceExportsCaptured=False,definitionEvidenceOnly=True,deviceOperations=0,nativeCPUCalls=0,
        frameworkLoads=0,full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(x)for x in (Path(__file__),hp,prefix,tail,cp,out/'request.json',out/'derivation.json',out/'source.py')]
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),freeze=p.pin(out/'freeze.json'),range=row)))

if __name__=='__main__':main()
