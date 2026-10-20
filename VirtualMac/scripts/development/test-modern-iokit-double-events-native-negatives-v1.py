#!/usr/bin/env python3
"""Verify genuine native packet comparisons reject bounded safe field mutations."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('iokit_negative_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE)and not out.exists()
    build=p.NODE/'iokit-double-events-data-build-v3/candidate.json'
    for pin in json.loads((build.parent/'freeze.json').read_bytes())['files']:assert p.pin(Path(pin['path']))==pin
    host=p.ROOT/'VirtualMac/vz/host'
    packet=host/'modern_iokit_double_event_packets.c';provider=host/'modern_iokit_double_events.c';fixture=host/'modern_iokit_double_events_fixture.c'
    original=packet.read_text()
    mutations=[
        ('force-stage-reserved-byte-overwrite','packet[20] = (uint8_t)stage;','write32(packet,20,stage);'),
        ('force-index-loss-of-upper-bits','write32(packet, 16, index);','write32(packet,16,(uint16_t)index);'),
        ('force-progress-missing-first-double','write_double(packet, 24, progress);','write_double(packet,32,progress);'),
        ('touch-nonzero-normalization-loss','packet[40] = touching != 0;','packet[40]=(touching & 1) != 0;'),
        ('touch-mask-loss-of-upper-bits','write32(packet, 44, mask);','write32(packet,44,(uint16_t)mask);'),
        ('touch-coordinate-order-reversed','write_double(packet, 48, x);\n    write_double(packet, 56, y);','write_double(packet,48,y);\n    write_double(packet,56,x);'),
        ('touch-pressure-z-order-reversed','write_double(packet, 24, z);\n    write_double(packet, 32, pressure);','write_double(packet,24,pressure);\n    write_double(packet,32,z);')]
    inputs=[Path(__file__),build,packet,provider,fixture,host/'modern_iokit_double_event_packets.h'];pins=list(map(p.pin,inputs))
    out.mkdir();commands=[];results=[]
    def run(label,argv,expected):
        done=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(done.stdout);(out/(label+'.stderr')).write_bytes(done.stderr)
        commands.append(dict(label=label,argv=list(map(str,argv)),exit=done.returncode,
            stdoutSHA256=hashlib.sha256(done.stdout).hexdigest(),stderrSHA256=hashlib.sha256(done.stderr).hexdigest()))
        p.save(out/'commands.json',commands)
        assert done.returncode==expected,(label,done.returncode,done.stderr)
        return done
    sdk=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path'],0).stdout.decode().strip()
    for label,before,after in mutations:
        assert original.count(before)==1
        source=out/(label+'.c');source.write_text(original.replace(before,after))
        exe=out/(label+'-ordinary-mac-fixture')
        flags=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos13.0','-isysroot',sdk,
            '-O2','-Wall','-Wextra','-Werror','-I'+str(host),'-DVM27_IOKIT_MAC_PACKET_FIXTURE',
            '-DVM27_FORCE_EVENT_EXPORT=VM27ForceStageFixture','-DVM27_TOUCH_EVENT_EXPORT=VM27TouchRadiusFixture']
        run(label+'-build',flags+[source,provider,fixture,'-framework','IOKit','-framework','CoreFoundation','-lobjc','-o',exe],0)
        done=run(label+'-execute',[exe],2)
        assert done.stderr==b'FAIL: all real original27 packet bytes\n'and not done.stdout
        deps=p.dependencies(exe.read_bytes())
        assert not any(any(word in row['path']for word in ('Hypervisor','Virtualization','VirtualMachineMonitor','UniversalHID'))for row in deps)
        results.append(dict(name=label,source=p.pin(source),executable=p.pin(exe),actualExit=2,
            actualExactNativePacketComparisonRejected=True,onlyOwnNativePacketInBoundsFieldsMutated=True,
            noDeviceOperations=True))
    assert pins==list(map(p.pin,inputs))
    p.save(out/'audit.json',dict(schema='Actual genuine IOKit native packet field functional negatives v1',inputs=pins,
        mutatedSourceFilesOnlyInNewLocalDirectory=True,frozenProductionSourceWholeBytesUnchanged=True,
        originalGenuineNamedConstructorsAndUUIDGuardUnchanged=True,negativeControls=results,
        onlyOrdinaryMacFixtureExecuted=True,deviceOperations=0,nativeHVCalls=0,originalHIDLoaded=False,
        originalVZLoaded=False,nativeIOSExecuted=False,full27Backend=False))
    files=[path for path in out.rglob('*')if path.is_file()]
    p.save(out/'freeze.json',dict(files=pins+list(map(p.pin,files)),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),negativeControls=len(results))))


if __name__=='__main__':main()
