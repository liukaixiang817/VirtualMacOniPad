#!/usr/bin/env python3
"""Execute ordinary Mac genuine IOKit packet/lifetime ABI comparisons only."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('iokit_packet_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE) and not out.exists()
    original=p.NODE/'iokit-three-original-abi-readonly-v5/audit.json'
    for pin in json.loads((original.parent/'freeze.json').read_bytes())['files']:assert p.pin(Path(pin['path']))==pin
    audit=json.loads(original.read_bytes());assert audit['originalIOKitUUID']=='0e4cf3e4b0c2312ab1470bd4978ef0b7'
    source=p.ROOT/'VirtualMac/vz/host/modern_iokit_event_packet_fixture.c'
    inputs=[Path(__file__),source,original];pins=[p.pin(path)for path in inputs]
    out.mkdir();commands=[];results=[]
    def run(label,argv):
        result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=list(map(str,argv)),exit=result.returncode,
            stdoutSHA256=hashlib.sha256(result.stdout).hexdigest(),stderrSHA256=hashlib.sha256(result.stderr).hexdigest()))
        p.save(out/'commands.json',commands)
        assert result.returncode==0,(label,result.stderr.decode())
        return result
    try:
        sdk=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).stdout.decode().strip()
        for role in ('normal','address-undefined-sanitized'):
            exe=out/(role+'-ordinary-genuine-iokit-fixture')
            flags=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos13.0','-isysroot',sdk,
                   '-O2','-Wall','-Wextra','-Werror']
            if role!='normal':flags+=['-fsanitize=address,undefined']
            run(role+'-build',flags+[source,'-framework','IOKit','-framework','CoreFoundation','-lobjc','-o',exe])
            imports=p.dependencies(exe.read_bytes())
            assert not any(any(word in row['path']for word in ('Hypervisor','Virtualization','VirtualMachineMonitor','UniversalHID'))for row in imports)
            result=run(role+'-execute',[exe]);actual=json.loads(result.stdout)
            assert not result.stderr and actual['realEventsCreatedAndReleased']==1024
            assert actual['realParentOwnedChildren']==512 and actual['allOriginalPacketBytesCompared']
            assert actual['originalIOKitUUID']==audit['originalIOKitUUID'] and actual['macDataOffset']==96
            assert actual['checks']>=9000 and not actual['ipadLayoutOrInitializerExecuted']
            results.append(dict(role=role,executable=p.pin(exe),actualOrdinaryMacResult=actual,
                executableDependencies=imports,actualGenuineSystemConstructorsExecuted=True))
        assert pins==[p.pin(path)for path in inputs]
        p.save(out/'audit.json',dict(schema='Ordinary genuine original27 IOKit event packet lifetime C ABI execution evidence v1',
            sources=pins,roles=results,originalCompleteMachineABI=p.pin(original),
            actualOriginal27MacConstructorsExecuted=True,forceStageType41Exact80Bytes=True,
            touchRadiusType42Exact96Bytes=True,allDoubleIEEEBitsAndTruncationCompared=True,
            realAppendRetainsChildThroughParentLifetime=True,ordinaryMacClassInstanceSize=104,ordinaryMacObjectDataOffset=96,
            currentIPadClassInstanceSizeOrInitializerNotEstablishedByMacTest=True,
            oldHostConstructorProviderImplemented=False,nativeIOSExecuted=False,originalUHLoaded=False,
            originalVZLoaded=False,nativeHVCalls=0,deviceOperations=0,full27Backend=False))
        p.save(out/'freeze.json',dict(files=pins+[p.pin(path)for path in out.rglob('*')if path.is_file()],deviceOperations=0))
        print(json.dumps(dict(audit=p.pin(out/'audit.json'),roles=results)))
    except Exception as error:
        failed=out/'failed-sources';failed.mkdir(exist_ok=True)
        for source in inputs:(failed/source.name).write_bytes(source.read_bytes())
        p.save(out/'failure.json',dict(error=repr(error),sources=pins,nativeIOSExecuted=False,deviceOperations=0))
        raise


if __name__=='__main__':main()
