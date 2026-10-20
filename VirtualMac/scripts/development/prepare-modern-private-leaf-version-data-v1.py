#!/usr/bin/env python3
"""Publish the existing finite private API as version 1 in unsigned inert data.

Only the two LC_ID_DYLIB version fields change. No system framework version is
advertised, no image is loaded or signed, and original caller gates stay false.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from macho_chained_import_records_v1 import read
spec = importlib.util.spec_from_file_location('version_frontier', HERE/'audit-modern-genuine-hid-current-frontier-v16.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
p, N = f.p, f.NODE
SPECS = [
    ('VM27ScopedDisplayRoutes.dylib', 'vz-scoped-display-routes-build-v1/VM27ScopedDisplayRoutes.dylib',
     'fd2cad7ebd658e5d4b6433b0d9e7a71d45b2a1b3cfc41fb6ff527d1752185a88',
     'vz-scoped-display-routes-build-v1/candidate.json',
     ['_SLMainDisplayID', '_SLSCopyDisplayInfoDictionary']),
    ('VM27ScopedStringCompare.dylib', 'vz-six-import-consumer-contract-v1/scoped-strcmp-build-v1/ios/VM27ScopedStringCompare.dylib',
     '7cd8b9ebe52c50192ace1d2b266d6f98ea9f25eef785e16aefa59605defc7b40',
     'vz-six-import-consumer-contract-v1/scoped-strcmp-build-v1/candidate.json', ['__platform_strcmp']),
    ('VM27ScopedSoftLinking.dylib', 'softlinking-app-private-local-v1/build-v4/ios/VM27ScopedSoftLinking.dylib',
     'c77b9f6136c7d7473d6e117595d9f06656d81717d8c053309e53d71611d335a8',
     'softlinking-app-private-local-v1/build-v4/candidate.json', ['__sl_dlopen'])]


def version_contract(raw):
    ids = [(at, size) for command, at, size in p.commands(raw) if command == 13]
    assert len(ids) == 1
    at, size = ids[0]
    offset, timestamp, current, compatibility = struct.unpack_from('<4I', raw, at+8)
    assert 24 <= offset < size
    end = raw.index(0, at+offset, at+size)
    name = raw[at+offset:end].decode()
    assert name.startswith(('@loader_path/VM27Scoped', '@rpath/VM27Scoped'))
    return dict(command=at, path=name, timestamp=timestamp, current=current, compatibility=compatibility)


def derive(source):
    identity = version_contract(source)
    assert identity['current'] == identity['compatibility'] == 0
    result = bytearray(source)
    struct.pack_into('<2I', result, identity['command']+16, 65536, 65536)
    return bytes(result)


def verify(source, target, names):
    assert target == derive(source)
    before, after = version_contract(source), version_contract(target)
    assert after == dict(before, current=65536, compatibility=65536)
    begin = before['command']+16
    assert source[:begin] == target[:begin] and source[begin+8:] == target[begin+8:]
    assert len(source) == len(target)
    assert p.segments(source) == p.segments(target)
    assert p.dependencies(source) == p.dependencies(target)
    assert read(source, p.commands) == read(target, p.commands)
    # The older generic word walker rejects some of these real SDK chain
    # formats. The exact whole-file complement above proves all chain words
    # are preserved without pretending that walker parsed an unsupported form.
    fixup = next(at for command, at, size in p.commands(source) if command == 0x80000034)
    fixup_offset, fixup_size = struct.unpack_from('<II', source, fixup+8)
    assert source[fixup_offset:fixup_offset+fixup_size] == target[fixup_offset:fixup_offset+fixup_size]
    # Read the original exact trie, rather than trusting the requested names.
    trie_command = next(at for command, at, size in p.commands(source) if command == 0x80000033)
    offset, size = struct.unpack_from('<II', source, trie_command+8)
    exports = f.s.primary.trie(source[offset:offset+size])
    assert set(exports) == set(names) and all(exports[name]['flags'] == 0 for name in names)
    assert source[offset:offset+size] == target[offset:offset+size]
    changed = [at for at, (a, b) in enumerate(zip(source, target)) if a != b]
    assert changed == [begin+2, begin+6]
    return dict(originalID=before, candidateID=after, changedOffsets=changed,
                allOtherWholeFileBytesPreserved=True, importsExportsAndDependenciesPreserved=True,
                allInstructionMetadataAndPACBytesPreserved=True, signatureStale=True,
                finiteOwnAPICompatibilityVersion=65536, wholeSystemFrameworkVersionAdvertised=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve(); assert out.is_relative_to(N) and not out.exists(); out.mkdir()
    rows, pins, negatives, tools = [], [], [], []
    for name, relative, sha, manifest, symbols in SPECS:
        source_path = N/relative; pin = p.pin(source_path); assert pin['sha256'] == sha
        raw = source_path.read_bytes(); result = derive(raw)
        candidate = out/(name+'.unsigned.inert.macho-data'); candidate.write_bytes(result); candidate.chmod(0o600)
        proof = verify(raw, result, symbols)
        parsed = read(raw, p.commands)
        def reject(label, body):
            try: verify(raw, body, symbols)
            except (AssertionError, ValueError, IndexError, StopIteration, struct.error):
                negatives.append(dict(owner=name, name=label, rejected=True)); return
            raise AssertionError('accepted damaged version-only candidate '+label)
        at = proof['originalID']['command']
        for label, position in [('current version', at+16), ('compatibility version', at+20),
                                ('install name', at+24), ('file header', 4),
                                ('active import schema', parsed['activeFixupsOffset'])]:
            damaged = bytearray(result); damaged[position] ^= 1; reject(label, bytes(damaged))
        reject('extra byte', result+b'\0')
        reject('unchanged source fails minimum version', raw)
        argv = ['xcrun', 'dyld_info', '-validate_only', str(candidate)]
        completed = subprocess.run(argv, capture_output=True, timeout=30)
        (out/(name+'.validate.stdout')).write_bytes(completed.stdout)
        (out/(name+'.validate.stderr')).write_bytes(completed.stderr)
        assert completed.returncode == 0
        tools.append(dict(argv=argv, exit=completed.returncode, imageExecuted=False))
        rows.append(dict(name=name.removesuffix('.dylib'), intendedLoadPath='@loader_path/'+name,
                         original=pin, candidate=p.pin(candidate), sourceCandidate=p.pin(N/manifest),
                         definitionSymbols=symbols, verification=proof, nativeIOSExecuted=False,
                         originalVZCallerExecuted=False, candidateReadyForNativeLoading=False))
        pins += [pin, p.pin(N/manifest), p.pin(candidate), p.pin(out/(name+'.validate.stdout')), p.pin(out/(name+'.validate.stderr'))]
    assert len(rows) == 3 and len(negatives) == 21
    report = dict(schema='Existing finite private API version-one inert data candidates v1',
                  providers=rows, negativeControls=negatives, staticTools=tools,
                  onlySixWholeFileBytesChangedAcrossThreeProviders=True,
                  signingCalls=0, inputImagesExecuted=False, originalVZLoaded=False,
                  processIdentityOrPolicyChanged=False, nativeIOSExecuted=False,
                  deviceOperations=0, full27Backend=False)
    p.save(out/'candidate.json', report)
    pins += [p.pin(x) for x in (Path(__file__), HERE/'macho_chained_import_records_v1.py', HERE/'audit-modern-genuine-hid-current-frontier-v16.py', out/'candidate.json')]
    p.save(out/'freeze.json', dict(files=pins, deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'), freeze=p.pin(out/'freeze.json'), rejectedControls=21)))


if __name__ == '__main__': main()
