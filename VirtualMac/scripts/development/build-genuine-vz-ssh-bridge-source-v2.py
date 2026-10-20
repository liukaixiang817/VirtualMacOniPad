#!/usr/bin/env python3
"""HOST-only V2 delegate ABI compile/link; reuse unchanged C socket owners.

No signing, App integration, original VZ callback or guest operation occurs.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
S = R / 'VirtualMac/vz/host'
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD = N / 'host-genuine-vz-ssh-bridge-local-v1-attempt1'

def pin(path):
    path = Path(path).resolve()
    value = path.read_bytes()
    return dict(path=str(path), bytes=len(value), sha256=hashlib.sha256(value).hexdigest())

def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists():
        raise ValueError('fresh output required')
    out.mkdir(parents=True)
    commands = []
    def run(label, argv):
        actual = subprocess.run([str(v) for v in argv], capture_output=True, timeout=60)
        stdout, stderr = out/(label+'.stdout'), out/(label+'.stderr')
        stdout.write_bytes(actual.stdout); stderr.write_bytes(actual.stderr)
        commands.append(dict(label=label, command=[str(v) for v in argv], exit=actual.returncode,
                             stdout=pin(stdout), stderr=pin(stderr)))
        save(out/'commands.json', commands)
        if actual.returncode:
            raise ValueError(label + ': ' + actual.stderr.decode(errors='replace'))
        return actual.stdout.decode()
    old = json.loads((OLD/'candidate.json').read_bytes())
    for row in json.loads((OLD/'freeze.json').read_bytes())['pins']:
        if pin(row['path']) != row:
            raise ValueError('unchanged original source/object pin: ' + row['path'])
    source = S/'vm27_genuine_vz_ssh_bridge_v2.m'
    oldsource = S/'vm27_genuine_vz_ssh_bridge_v1.m'
    header = S/'vm27_genuine_vz_ssh_bridge_v2.h'
    fixture = S/'test-vm27-vz-ssh-delegate-abi-v2.m'
    save(out/'source-diff.json', dict(oldSource=pin(oldsource), newSource=pin(source)))
    (out/'v1-to-v2.diff').write_text(''.join(difflib.unified_diff(oldsource.read_text().splitlines(True),
        source.read_text().splitlines(True), fromfile=str(oldsource), tofile=str(source))))
    mac = Path(run('actual-mac-sdk', ['xcrun','--sdk','macosx','--show-sdk-path']).strip())
    ios = Path(run('actual-ios-sdk', ['xcrun','--sdk','iphoneos','--show-sdk-path']).strip())
    iosobject = out/'vm27_genuine_vz_ssh_bridge_v2.ios.o'
    common = ['-fPIC','-Wall','-Wextra','-Werror','-fobjc-arc','-fblocks']
    run('actual-ios-compile', ['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',ios,
        *common,'-c',source,'-o',iosobject])
    stems = ['vm27_host_vsock_ssh_owner_v1','vm27_owned_stream_relay_v1','vm27_vsock_ssh_protocol_v1']
    ios_c = [OLD/(stem+'.ios.o') for stem in stems]
    mac_c = [OLD/(stem+'.mac.o') for stem in stems]
    iosdso = out/'VM27GenuineVZSSHBridgeV2.ios.dylib'
    run('actual-ios-strict-link', ['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',ios,
        '-dynamiclib',*ios_c,iosobject,'-framework','Foundation','-Wl,-undefined,error',
        '-Wl,-no_adhoc_codesign','-o',iosdso])
    newundefined = run('actual-ios-undefined', ['xcrun','nm','-u',iosdso])
    oldundefined = run('original-ios-undefined', ['xcrun','nm','-u',OLD/'VM27GenuineVZSSHBridgeV1.ios.dylib'])
    defined = run('actual-ios-exports', ['xcrun','nm','-gU',iosdso])
    originaldefined = run('original-ios-exports', ['xcrun','nm','-gU',OLD/'VM27GenuineVZSSHBridgeV1.ios.dylib'])
    symbols = lambda text: {line.split()[-1] for line in text.splitlines() if line.split()}
    if symbols(defined) != symbols(originaldefined):
        raise ValueError('public V1 class/factory ABI must remain identical')
    added = sorted(symbols(newundefined)-symbols(oldundefined))
    removed = sorted(symbols(oldundefined)-symbols(newundefined))
    expected = {'_class_getInstanceMethod','_method_getArgumentType',
                '_method_getNumberOfArguments','_method_getReturnType','_strcmp'}
    if set(added) != expected or set(removed) != {'_class_addProtocol','_class_conformsToProtocol','_objc_getProtocol'}:
        raise ValueError('only actual named method metadata imports may change')
    if 'OBJC_CLASS_$_VZ' in newundefined:
        raise ValueError('no static Apple VZ class substitute/import')
    run('actual-ios-validate', ['xcrun','dyld_info','-validate_only',iosdso])
    actualfixture = out/'actual-own-objc-metadata'
    run('actual-own-metadata-link', ['xcrun','clang','-target','arm64-apple-macos15',
        '-isysroot',mac,*common,fixture,*mac_c,'-framework','Foundation','-o',actualfixture])
    result = run('actual-own-metadata-run', [actualfixture])
    if 'actualOwnObjCMetadataChecks=8' not in result or 'listenersOpened=0' not in result:
        raise ValueError('eight actual own metadata checks required')
    typed = out/'typed-header.mm'
    typed.write_text('#import "vm27_genuine_vz_ssh_bridge_v2.h"\n'
        'BOOL ActualABI(id vm,NSString*path,VM27GenuineVZSSHBridgeV1**owner,NSError**error) {\n'
        'return VM27CreateGenuineVZSSHBridgeV1(vm,path,30000,owner,error);}\n')
    run('actual-ios-cxx-header', ['xcrun','clang++','-target','arm64e-apple-ios16.1',
        '-isysroot',ios,*common,'-I',S,'-c',typed,'-o',out/'typed-header.ios.o'])
    cppsymbols = run('actual-cxx-symbols', ['xcrun','nm','-u',out/'typed-header.ios.o'])
    if '_VM27CreateGenuineVZSSHBridgeV1' not in cppsymbols:
        raise ValueError('same unmangled C factory ABI required')
    headers = mac/'System/Library/Frameworks/Virtualization.framework/Versions/A/Headers'
    sdkpins = [pin(headers/name) for name in ('VZVirtioSocketListener.h','VZVirtioSocketDevice.h')]
    indexpath = N/'current-native-header-export-index-v3/index.json'
    index = json.loads(indexpath.read_bytes())
    native = []
    for name in added:
        path = '/usr/lib/system/libsystem_c.dylib' if name == '_strcmp' else '/usr/lib/libobjc.A.dylib'
        requestedPath, requestedName = path, name
        route = []
        image = index['images'][path]
        definition = image['definitions'][name]
        while definition['flags'] & 8:
            if (path,name) in route or len(route) >= 8:
                raise ValueError('finite native alias route required')
            route.append((path,name))
            path = next(row['path'] for row in image['dependencies']
                        if row['ordinal'] == definition['ordinal'])
            name = definition.get('alias') or definition.get('importedName') or name
            image = index['images'][path]
            definition = image['definitions'][name]
        native.append(dict(requestedPath=requestedPath, requestedSymbol=requestedName,
            aliasRoute=route, symbol=name, path=path, UUID=image['UUID'], definition=definition))
    candidate = dict(schema='Named genuine VZ SSH delegate implementation source V2',
        status='HELD_HOST_ONLY_NO_APP20_INTEGRATION', source=pin(source), header=pin(header),
        oldSource=pin(oldsource), oldPublicHeader=pin(S/'vm27_genuine_vz_ssh_bridge_v1.h'),
        iosObject=pin(iosobject), actualStrictLinkedIOS=pin(iosdso), actualIOSCompileLinkValidatePassed=True,
        publicV1ABIUnchanged=True, actualOwnMetadataChecks=8, genuineVZRuntimeTested=False,
        actualAppleProtocolCreated=False, requiresOriginalProtocolObject=False,
        namedCallback='listener:shouldAcceptNewConnection:fromSocketDevice:',
        requiredCallbackShape='BOOL(@,SEL,@,@,@)', actualListenerSetterShape='void(@,SEL,@)',
        addedNativeImports=added, removedNativeImports=removed, addedActualNativeDefinitions=native,
        currentNativeIndex=pin(indexpath), genuineSDKContracts=sdkpins,
        productionPorts=dict(listener=22223, hostTCP='127.0.0.1:22222', guestTCP='127.0.0.1:22'),
        preserved='4 genuine image/class checks, actual VM.queue, exact one socket device, associated VM owner, native listener registration, duplicate FD/genuine connection lease, C control nonce/sequence, drain/close',
        futureBuildMustReplaceV1TranslationUnit=True, app20Integrated=False, deviceOperations=0,
        signingOperations=0, actualGuestHelperInstalled=False, actualSSHAuthenticated=False,
        persistentGuestServiceHandoffImplemented=False, unchangedCOwnerSocketModelsNotRerun=True,
        inheritedBridgeCandidate=pin(OLD/'candidate.json'), commands=pin(out/'commands.json'))
    cp=out/'candidate.json';save(cp,candidate)
    inputs=[Path(__file__).resolve(),source,header,oldsource,S/'vm27_genuine_vz_ssh_bridge_v1.h',fixture,
        OLD/'candidate.json',OLD/'freeze.json',indexpath,*ios_c,*mac_c]+[Path(v['path']) for v in sdkpins]
    files=inputs+[p for p in out.iterdir() if p.is_file()]
    save(out/'freeze.json',dict(files=list({p['path']:p for p in map(pin,files)}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=pin(cp),freeze=pin(out/'freeze.json'))))

if __name__ == '__main__':
    main()
