#!/usr/bin/env python3
"""Build an audited, build-specific ARM64e shared-radio driver; does not deploy it."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess

# Exact official VMAPPLE collections audited for the requested 15/26/27 review.
# Inclusion permits a development build, never a claim of runtime compatibility.
AUDITED_KERNELS = {
    '24G90': ('C419C604-58D6-F477-1FBC-1670F16512F3',
              '333e6c7e8a8082f9a2cc6ce021a5664e6cdc2b5eac2f34b822886c844a6b91f8'),
    '25G83': ('1156860D-0EC5-ED95-4813-2677A8109AD7',
              '268f431e7366409dc798cd8f719a93cf3a30c6f828201d8eeceae889358099c6'),
    '26A5416b': ('BA6D493F-999F-0208-8866-DC4865B06748',
                  '0fe14b0bf2d447b269e74b8f3b2cc8c008275c86c5c8e7fb1ef000bbddcaf4f2'),
    '26B131': ('270F6AC5-1ADD-9189-68B9-C5F940464907',
               'b9dd1cdf46a499b43fbd2a304ee0da2a2311bfbde5f7bc7bd1cf1e3b9c4b8142'),
}

PAYLOAD_LAYOUTS = {
    '24G90': {'beaconHeaderBytes': 0x40, 'extendedRsnOffset': 0xdd, 'extendedBeVersionOffset': 0, 'lqmBytes': 0x150},
    '25G83': {'beaconHeaderBytes': 0x44, 'extendedRsnOffset': 0x113, 'extendedBeVersionOffset': 0, 'lqmBytes': 0x1dc},
    '26A5416b': {'beaconHeaderBytes': 0x44, 'extendedRsnOffset': 0x120, 'extendedBeVersionOffset': 0xdc, 'lqmBytes': 0x250},
    # The four native payload producers retain the audited 27.0 layout;
    # 27.2.1 requires newly generated headers for its additional virtual slot.
    '26B131': {'beaconHeaderBytes': 0x44, 'extendedRsnOffset': 0x120, 'extendedBeVersionOffset': 0xdc, 'lqmBytes': 0x250},
}


def has_low_latency_handler(headers):
    # A pure virtual slot is named ___cxa_pure_virtual in the kernel's
    # vtable. Its existence is recorded by the audited generated declaration,
    # not by the address's symbol name in that table.
    return bool(re.search(r'\bgetWCL_LOW_LATENCY_INFO\s*\(',
                          (headers / 'IO80211InfraProtocol.h').read_text()))


def reject_unresolved_owned_symbols(output):
    missing = [line.strip() for line in output.splitlines()
               if 'VM27Shared' in line]
    if missing:
        raise ValueError('driver has unresolved own implementations: ' + ', '.join(missing))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--abi', type=Path, required=True)
    p.add_argument('--headers', type=Path, required=True)
    p.add_argument('--sdk-overlay', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--bundle-version', default='0.2.0')
    a = p.parse_args()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',a.bundle_version):
        raise ValueError('bundle version must have three numeric components')
    root = Path(__file__).resolve().parents[3]
    radio = root / 'VirtualMac/vz/shared-radio'
    vendor = radio / 'third_party/wtl_native'
    for name, digest in json.loads((vendor/'PROVENANCE.json').read_text())['files'].items():
        if hashlib.sha256((vendor/name).read_bytes()).hexdigest() != digest:
            raise ValueError('vendored reference changed: '+name)
    facts = json.loads((a.abi/'source.json').read_text())
    generated = json.loads((a.headers/'abi.json').read_text())
    profile = AUDITED_KERNELS.get(facts['build'])
    if (facts['architecture'] != 'arm64e' or not profile or
        (facts['uuid'], facts['sha256']) != profile or generated['kc_sha256'] != facts['sha256'] or
        generated['build'] != facts['build']):
        raise ValueError('requires an exact audited ARM64e kernel and its own generated headers')
    out = a.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    classes = json.loads((a.abi/'classes.json').read_text())
    pins = '#ifdef __cplusplus\n#include <IOKit/IOService.h>\n#include <IOKit/IOUserClient.h>\n#include <IOKit/IOWorkLoop.h>\n'
    payload = PAYLOAD_LAYOUTS[facts['build']]
    for name, key in [('BEACON_HEADER_BYTES', 'beaconHeaderBytes'),
                      ('EXTENDED_RSN_OFFSET', 'extendedRsnOffset'),
                      ('EXTENDED_BE_VERSION_OFFSET', 'extendedBeVersionOffset'),
                      ('LQM_BYTES', 'lqmBytes')]:
        pins += '#define VM27_NATIVE_' + name + ' ' + hex(payload[key]) + '\n'
    # 27 can publish en2 after airportd's initial inventory. Such interfaces
    # start unavailable until the native driver-available event arrives.
    # Keep the accepted 15/26 compiled paths unchanged.
    availability_event = facts['build'] in ('26A5416b', '26B131')
    pins += '#define VM27_NATIVE_DRIVER_AVAILABLE_EVENT_BYTES ' + ('0xf8' if availability_event else '0') + '\n'
    stubs = (a.headers/'iface_stubs.inc').read_text()
    pins += '#define VM27_NATIVE_LINK_STATE_UPDATE_PURE '+str(int('setWCL_LINK_STATE_UPDATE(' in stubs))+'\n'
    low_latency = has_low_latency_handler(a.headers)
    pins += '#define VM27_NATIVE_HAS_LOW_LATENCY_INFO_SLOT '+str(int(low_latency))+'\n'
    link_state = re.search(r'\bbool setLinkState\(([^)]*)\)', (a.headers/'IO80211InfraInterface.h').read_text())
    link_arguments = len(link_state[1].split(',')) if link_state else 0
    if link_arguments not in (4,5):
        raise ValueError('unreviewed native setLinkState signature')
    pins += '#define VM27_NATIVE_LINK_STATE_ARGUMENTS '+str(link_arguments)+'\n'
    all_headers = '\n'.join(path.read_text() for path in a.headers.glob('*.h'))
    pins += '#define VM27_NATIVE_MAC_ADDRESS_ETHER '+str(int('setMacAddress(ether_addr&' in all_headers))+'\n'
    pins += '#define VM27_NATIVE_ABORT_JOIN_VOID '+str(int('setWCL_JOIN_ABORT(void*' in all_headers))+'\n'
    for name in ['IOService','IOUserClient','IOWorkLoop']:
        pins += 'static_assert(sizeof('+name+') == '+str(classes[name]['size'])+', "exact '+facts['build']+' '+name+' size");\n'
    (out/'sdk-size-pins.h').write_text(pins+'#endif\n')
    contents = out/'VM27SharedRadioNativeV1.kext/Contents'
    (contents/'MacOS').mkdir(parents=True, exist_ok=True)
    identifier = 'com.virtualmac.SharedRadioNativeV1'
    info = {'CFBundleIdentifier':identifier,'CFBundleExecutable':'VM27SharedRadioNativeV1',
            'CFBundleName':'VirtualMac Shared Radio','CFBundlePackageType':'KEXT',
            'CFBundleVersion':a.bundle_version,'CFBundleShortVersionString':a.bundle_version, 'OSBundleRequired':'Console',
            'OSBundleLibraries':{name:'1.0.0' for name in [
                'com.apple.kpi.bsd','com.apple.kpi.iokit','com.apple.kpi.libkern','com.apple.kpi.mach',
                'com.apple.iokit.IONetworkingFamily','com.apple.iokit.IO80211Family',
                'com.apple.iokit.IOSkywalkFamily','com.apple.driver.corecapture']},
            'IOKitPersonalities':{
                'VirtualMac shared radio backend':{'CFBundleIdentifier':identifier,
                    'IOClass':'VM27SharedRadioBackendV1','IOProviderClass':'IOResources',
                    'IOResourceMatch':'IOKit','IOMatchCategory':'VM27SharedRadioBackendV1'},
                'VirtualMac native Wi-Fi':{'CFBundleIdentifier':identifier,
                    'IOClass':'VM27SharedWiFiControllerV1','IOProviderClass':'VM27SharedRadioBackendV1',
                    'IOMatchCategory':'VM27SharedWiFiControllerV1','MtkNativeEnabled':True,'MtkNativeInterface':True,
                    'MtkNativeAbi':{'Builds':[{'Build':facts['build'],'Xnu':facts['xnu'],'Sizes':generated['sizes']}]}}}}
    for name in ['com.apple.kpi.bsd','com.apple.kpi.iokit','com.apple.kpi.libkern','com.apple.kpi.mach']:
        info['OSBundleLibraries'][name] = '14.0.0'
    info['OSBundleLibraries']['com.apple.driver.corecapture'] = '1.0.4'
    (contents/'Info.plist').write_bytes(plistlib.dumps(info))
    sdk = Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    resources = Path(subprocess.check_output(['xcrun','clang','-print-resource-dir'],text=True).strip())
    src = radio/'guest/kernel/native'
    sources = [src/n for n in ['VM27SharedRadioBackendV1.cpp','VM27SharedWiFiControllerV1.cpp',
        'VM27SharedWiFiInterfaceV1.cpp','VM27SharedWiFiControllerV1Req.cpp']]
    sources += [vendor/'src/MtkNativeTrace.cpp', radio/'guest/kernel/vm27_shared_radio_kmod_info_v1.c']
    flags = ['-target','arm64e-apple-macos15.0','-mkernel','-nostdinc','-fno-builtin',
        '-fno-common','-fno-stack-protector','-DKERNEL','-DKERNEL_PRIVATE','-DDRIVER_PRIVATE','-DAPPLE','-DNeXT',
        '-isystem',str(resources/'include'),'-I',str(a.sdk_overlay.resolve()),
        '-I',str(sdk/'System/Library/Frameworks/Kernel.framework/Headers'),
        '-I',str(a.headers.resolve()),'-I',str(vendor/'src'),'-I',str(src),
        '-include',str(out/'sdk-size-pins.h'),
        '-O2','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-deprecated-declarations',
        '-Wno-inconsistent-missing-override','-Wno-mismatched-tags']
    commands=[]
    def run(label, argv):
        argv=list(map(str,argv));r=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (out/(label+'.log')).write_bytes(r.stdout);commands.append({'label':label,'argv':argv,'exit':r.returncode})
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if r.returncode: raise RuntimeError(label+': '+r.stdout.decode(errors='replace')[-6000:])
        return r.stdout
    objects=[]
    for index, source in enumerate(sources):
        obj=out/(source.stem+'.o'); cpp=source.suffix=='.cpp'
        extra=['-fapple-kext','-std=gnu++17','-nostdinc++','-fno-exceptions','-fno-rtti',
               '-fno-use-cxa-atexit','-fno-register-global-dtors-with-atexit'] if cpp else ['-DVM27_MODULE_ID='+identifier, '-DVM27_MODULE_VERSION="'+a.bundle_version+'"']
        run('compile-'+str(index),['xcrun','clang++' if cpp else 'clang',*flags,*extra,'-c',source,'-o',obj])
        if cpp: run('llvm-'+str(index),['xcrun','clang++',*flags,*extra,'-S','-emit-llvm',source,'-o',out/(source.stem+'.ll')])
        objects.append(obj)
    audits = {}
    for name, unit, parent in [
            ('VM27SharedRadioBackendV1','VM27SharedRadioBackendV1','IOService'),
            ('VM27SharedRadioUserClientV1','VM27SharedRadioBackendV1','IOUserClient'),
            ('VM27SharedWiFiControllerV1','VM27SharedWiFiControllerV1','IO80211Controller'),
            ('VM27SharedWiFiInterfaceV1','VM27SharedWiFiInterfaceV1','IO80211InfraProtocol')]:
        symbol = '_ZTV'+str(len(name))+name
        slots = {}
        for line in (out/(unit+'.ll')).read_text().splitlines():
            if 'section "llvm.ptrauth"' not in line or 'ptr @'+symbol+',' not in line: continue
            slot = re.search(r'ptr @'+symbol+r', i32 0, i32 0, i32 (\d+)\) to i64\), i64 (\d+)',line)
            key = re.search(r', i32 (\d+), i64 ptrtoint',line)
            if slot and key: slots[int(slot[1])] = {'key':int(key[1]),'diversity':int(slot[2]),'addressDiversity':True}
        compared = 0; mismatch = []
        for native in classes[parent]['vtable']:
            if not native['authenticated']: continue
            compared += 1; compiled = slots.get(native['slot'])
            if not compiled or any(compiled[k]!=native[k] for k in ['key','diversity','addressDiversity']):
                mismatch.append({'native':native,'compiled':compiled})
        audits[name] = {'parent':parent,'compared':compared,'mismatches':mismatch}
    (out/'concrete-driver-ptrauth-audit-v1.json').write_text(json.dumps(audits,indent=2)+'\n')
    if any(not r['compared'] or r['mismatches'] for r in audits.values()): raise ValueError('actual driver ARM64e vtable signatures differ from the guest kernel')
    binary=contents/'MacOS/VM27SharedRadioNativeV1'
    run('link',['xcrun','clang++','-target','arm64e-apple-macos15.0','-nostdlib','-Wl,-kext','-Wl,-export_dynamic',
        *objects,'-L'+str(sdk/'usr/lib'),'-lkmodc++','-lkmod',resources/'lib/darwin/libclang_rt.cc_kext.a','-o',binary])
    run('xattrs',['xattr','-cr',contents.parent]);run('sign',['codesign','--force','--sign','-','--timestamp=none',contents.parent])
    run('verify-signature',['codesign','--verify','--strict',contents.parent])
    undefined = run('undefined-symbols',['nm','-u',binary]).decode()
    # Kext linking allows imports. An omitted override must never become an
    # import that runtime vtable patching can replace with a pure base slot.
    reject_unresolved_owned_symbols(undefined)
    manifest={'schema':1,'kext':str(contents.parent),'identifier':identifier,'targetKernel':facts,
        'binarySHA256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'sources':{str(s.relative_to(root)):hashlib.sha256(s.read_bytes()).hexdigest() for s in sources},
        'guestDeploymentPerformed':False,'nativeScanValidated':False,'associationDataPathReady':False}
    manifest['concreteDriverPointerSignaturesMatch'] = True
    manifest['wirelessPayloadLayout'] = payload
    payload_source = src/'VM27SharedWiFiPayloadLayoutV1.h'
    manifest['sources'][str(payload_source.relative_to(root))] = hashlib.sha256(payload_source.read_bytes()).hexdigest()
    availability_source = src/'VM27SharedWiFiAvailabilityV1.h'
    manifest['sources'][str(availability_source.relative_to(root))] = hashlib.sha256(availability_source.read_bytes()).hexdigest()
    manifest['nativeDriverAvailabilityEvent'] = {
        'enabled': availability_event, 'event': 0x37,
        'bytes': 0xf8 if availability_event else 0,
        'requiresRealHostTransportAndGuestPower': True,
        'associationClaimedByEvent': False,
    }
    manifest['authenticatedSlotsCompared'] = sum(r['compared'] for r in audits.values())
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))


if __name__=='__main__':main()
