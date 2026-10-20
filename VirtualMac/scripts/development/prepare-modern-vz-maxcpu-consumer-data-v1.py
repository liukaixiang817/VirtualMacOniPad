#!/usr/bin/env python3
"""Prepare inert original27 VZ data: route only the maxVCPU leaf import.

No signing, loading, syscall, deployment or original-image execution occurs.
The original Hypervisor dependency and maxIPA import remain unresolved here.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER = N / 'vz-typed-routes-independent-review-v1/review.py'
READER_SHA = 'a9dc92b4bb4d732b02df7b6ac9b91ce3c0a5dacd43f675d6fefcff261fb6aae4'
SOURCE = N / 'vz-efi27-original-route-v1/build-v2/VZ27.efi27-original-route.inert.macho-data'
SOURCE_SHA = '3154c7b3543bed1f8ef3372acaa36ead0514a1c74d53058a57dafb2f97ab59bd'
PROVIDER = N / 'hv-framework-max-vcpu-contract-v1/ios/VM27FrameworkLimits.dylib'
PROVIDER_SHA = '71a792922c322806cc62b2f9cf3ab6fe143b33e7da383675cef649b7a8652310'
PATH = '@loader_path/VL'
SYMBOL = '_hv_vm_get_max_vcpu_count'
assert hashlib.sha256(READER.read_bytes()).hexdigest() == READER_SHA
spec = importlib.util.spec_from_file_location('bounded_vz_reader', READER)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def commands(b):
    assert len(b) >= 32 and struct.unpack_from('<I', b)[0] == 0xfeedfacf
    count, size = struct.unpack_from('<II', b, 16)
    assert count < 256 and 32 + size <= len(b)
    at = 32
    result = []
    for _ in range(count):
        c, z = struct.unpack_from('<II', b, at)
        assert z >= 8 and z % 8 == 0 and at + z <= 32 + size
        result.append((c, at, z))
        at += z
    assert at == 32 + size
    return result


def uleb(b, at, end):
    value = 0
    for shift in range(0, 64, 7):
        assert at < end
        x = b[at]
        at += 1
        if shift == 63:
            assert x < 2
        value |= (x & 127) << shift
        if not x & 128:
            return value, at
    raise AssertionError('ULEB overflow')


def provider_proof(b):
    assert m.sha(b) == PROVIDER_SHA
    ids, deps, builds, init_sections = [], [], [], []
    export = None
    uuids = []
    for c, at, z in commands(b):
        if c in m.DEP_COMMANDS or c == 13:
            no, t, current, compatibility = struct.unpack_from('<4I', b, at + 8)
            assert 24 <= no < z
            name, _ = m.checked_string(b, at + no, at + z)
            (ids if c == 13 else deps).append(dict(command=c, path=name,
                                                 metadata=[t, current, compatibility]))
        elif c == 0x32:
            builds.append(list(struct.unpack_from('<4I', b, at + 8)))
        elif c == 0x1b:
            assert z == 24
            uuids.append(b[at + 8:at + 24].hex())
        elif c == 0x80000022:
            assert export is None
            info = list(struct.unpack_from('<10I', b, at + 8))
            assert info[2:8] == [0] * 6
            export = info[8:10]
        elif c == 0x80000033:
            assert export is None and z == 16
            export = list(struct.unpack_from('<II', b, at + 8))
        elif c == 0x19:
            ns = struct.unpack_from('<I', b, at + 64)[0]
            assert z == 72 + 80 * ns
            for i in range(ns):
                sa = at + 72 + 80 * i
                section_size = struct.unpack_from('<Q', b, sa + 40)[0]
                flags = struct.unpack_from('<I', b, sa + 64)[0]
                if flags & 255 in (9, 10):
                    init_sections.append((flags & 255, section_size))
        elif c == 11:
            assert struct.unpack_from('<I', b, at + 28)[0] == 0
    assert len(ids) == 1 and ids[0] == dict(command=13, path='@rpath/VM27FrameworkLimits.dylib', metadata=[1, 65536, 65536])
    assert len(deps) == 1 and deps[0]['command'] == 12 and deps[0]['path'] == '/usr/lib/libSystem.B.dylib'
    assert len(builds) == 1 and builds[0][0] == 2 and builds[0][1] == 0x100100
    assert not init_sections and export is not None and len(uuids) == 1
    start, size = export
    assert size > 0 and start + size <= len(b)
    found = {}
    seen = set()

    def node(offset, prefix):
        assert 0 <= offset < size and offset not in seen and len(prefix) < 512
        seen.add(offset)
        at = start + offset
        terminal, at = uleb(b, at, start + size)
        end = at + terminal
        assert end <= start + size
        if terminal:
            flags, at = uleb(b, at, end)
            address, at = uleb(b, at, end)
            assert flags == 0 and address > 0 and at == end and prefix not in found
            found[prefix] = dict(flags=flags, address=address)
        at = end
        assert at < start + size
        children = b[at]
        at += 1
        links = []
        for _ in range(children):
            edge, at = m.checked_string(b, at, start + size)
            assert edge
            child, at = uleb(b, at, start + size)
            links.append((child, prefix + edge))
        for child, prefix in links:
            node(child, prefix)
    node(0, '')
    assert set(found) == {SYMBOL}
    return dict(ID=ids[0], UUID=uuids[0], strongDependencies=deps, build=builds[0], exports=found,
                imports=0, initializers=0, actualIOSExecution=False,
                maximumIsFrameworkUpperBound=True, host64CPUsValidated=False)


def derive(source):
    assert m.sha(source) == SOURCE_SHA and len(source) == 4212080
    a = m.parse(source)
    assert a['header'][3:5] == [78, 9552] and len(a['deps']) == 59
    raws = []
    for row in a['commands']:
        raw = row['raw']
        if row.get('ordinal') == 32:
            minimum = (row['tail'] - row['at'] + 7) & ~7
            assert row['name'] == '@loader_path/EfiSupport27.dylib' and row['size'] == 96 and minimum == 56
            assert raw[56:] == bytes(40)
            raw = bytearray(raw[:56])
            struct.pack_into('<I', raw, 4, 56)
            raw = bytes(raw)
        raws.append(raw)
    path = PATH.encode() + b'\0'
    assert (24 + len(path) + 7) & ~7 == 40
    raw = struct.pack('<6I', 12, 40, 24, 2, 65536, 65536) + path
    assert len(raw) == 40
    raws.append(raw)
    expected = bytearray(source)
    expected[32:9584] = b''.join(raws)
    struct.pack_into('<I', expected, 16, 79)
    selected = a['imports'][560]
    assert selected['name'] == SYMBOL and selected['ordinal'] == 26 and selected['weak'] is False and selected['addend'] == 0
    expected[selected['at']] = 60
    nlists = [r for r in a['nlists'] if r['name'] == SYMBOL]
    assert len(nlists) == 1
    row = nlists[0]
    assert row['type'] == 1 and row['section'] == row['value'] == 0 and row['desc'] == 26 << 8
    expected[row['at'] + 7] = 60
    return bytes(expected)


def verify(source, candidate, provider):
    provider_info = provider_proof(provider)
    assert derive(source) == candidate
    a = m.parse(source)
    b = m.parse(candidate)
    assert len(candidate) == len(source) and b['header'][3:5] == [79, 9552]
    assert a['segments'] == b['segments'] and a['words'] == b['words'] and len(b['words']) == 26993
    assert len(b['deps']) == 60 and len(a['imports']) == len(b['imports']) == 1056
    assert b['deps'][-1]['cmd'] == 12 and b['deps'][-1]['name'] == PATH and b['deps'][-1]['versions'] == [2, 65536, 65536]
    for x, y in zip(a['deps'], b['deps']):
        assert (x['cmd'], x['ordinal'], x['name'], x['nameOffset'], x['versions']) == (y['cmd'], y['ordinal'], y['name'], y['nameOffset'], y['versions'])
    for x, y in zip(a['imports'], b['imports']):
        expected = dict(x)
        if x['index'] == 560:
            expected['ordinal'] = 60
        assert y == expected
    for x, y in zip(a['nlists'], b['nlists']):
        expected = dict(x)
        if x['name'] == SYMBOL:
            expected['desc'] = 60 << 8
        assert y == expected
    for segment in a['segments']:
        for section in segment['sections']:
            at, size = section['at'], section['bytes']
            if at and size and section['flags'] & 255 not in (1, 12, 18):
                assert source[at:at + size] == candidate[at:at + size]
    nlist = next(r for r in a['nlists'] if r['name'] == SYMBOL)
    changes = [i for i, (x, y) in enumerate(zip(source, candidate)) if x != y]
    outside = sorted({i for i in changes if i >= 9584})
    assert outside == sorted([a['imports'][560]['at'], nlist['at'] + 7])
    assert b['imports'][559] == a['imports'][559]
    assert a['deps'][25]['name'] == b['deps'][25]['name'] == '/System/Library/Frameworks/Hypervisor.framework/Hypervisor'
    return dict(selectedImport=b['imports'][560], changedBeyondHeader=outside,
                changedBytes=len(changes), maxIPAImportUnchanged=b['imports'][559],
                originalHypervisorDependencyRetained=True, originalHypervisorOtherExportsSatisfied=False,
                chainWordsExact=26993, codeAndDataSectionsUnchanged=True,
                allPreviousRoutesRetained=True, headerBytesUnchanged=9552,
                EFIOnlyTrailing40NULBytesCompacted=True, provider=provider_info,
                signatureStale=True, aliasRequirement=dict(path='VL', byteExactProvider=m.pin(PROVIDER),
                    sameNewPrivateDeploymentDirectoryAsConsumer=True, ordinaryFile=True,
                    requiredLinkCount=1, symlinksPermitted=False, hardlinksPermitted=False,
                    providerOriginalIDRetained=True, replacesNoSystemPath=True))


def negatives(source, candidate, provider):
    p = m.parse(candidate)
    cases = []
    def bad(name, damaged, prov=provider):
        try:
            verify(source, damaged, prov)
        except (AssertionError, ValueError, IndexError, struct.error):
            cases.append(dict(name=name, rejected=True))
            return
        raise AssertionError('Accepted damaged candidate: ' + name)
    selected = p['imports'][560]
    nl = next(r for r in p['nlists'] if r['name'] == SYMBOL)
    chain = next(r for r in p['words'] if r['bind'] and r['index'] == 560)
    for label, at, mask in [('query ordinal', selected['at'], 1), ('query weak', selected['at'] + 1, 1),
                           ('query addend', selected['at'] + 4, 1), ('query nlist ordinal', nl['at'] + 7, 1),
                           ('unselected maxIPA', p['imports'][559]['at'], 1), ('PAC', chain['at'] + 7, 128),
                           ('instruction', 9584, 1), ('original typed import', p['imports'][42]['at'], 1),
                           ('header count', 16, 1), ('old HV compatibility', p['deps'][25]['at'] + 20, 1),
                           ('EFI path', p['deps'][31]['at'] + 24, 1), ('provider path', p['deps'][-1]['at'] + 24, 1),
                           ('provider minimum version', p['deps'][-1]['at'] + 20, 1)]:
        q = bytearray(candidate)
        q[at] ^= mask
        bad(label, bytes(q))
    q = bytearray(candidate)
    struct.pack_into('<I', q, p['deps'][-1]['at'], 0x80000018)
    bad('genuine weak load', bytes(q))
    q = bytearray(provider)
    q[-1] ^= 1
    bad('provider bytes', candidate, bytes(q))
    bad('trailing bytes', candidate + b'\0')
    return cases


def run(out, check):
    source = SOURCE.read_bytes()
    provider = PROVIDER.read_bytes()
    target = out / 'VZ27.maxcpu-leaf-route.inert.macho-data'
    alias = out / 'VL'
    if check:
        c = m.json_read(out / 'candidate.json')
        assert c['builder'] == m.pin(pathlib.Path(__file__))
        assert c['reader'] == m.pin(READER)
        assert c['source'] == m.pin(SOURCE) and c['provider'] == m.pin(PROVIDER)
        assert c['binary'] == m.pin(target) and stat.S_IMODE(target.stat().st_mode) == 0o600
        alias_info = alias.lstat()
        assert stat.S_ISREG(alias_info.st_mode) and alias_info.st_nlink == 1 and not alias.is_symlink()
        assert alias.read_bytes() == provider and c['providerAlias'] == m.pin(alias)
        assert c['providerCDHash'] == 'e718d5b10cdf2d472a46b006fc23729da1d157b1'
        assert c['verification'] == verify(source, target.read_bytes(), provider)
        assert negatives(source, target.read_bytes(), provider) == m.json_read(out / 'negative-controls.json')
        print(json.dumps(dict(passed=True, checkedSavedCandidate=True, binary=m.pin(target))))
        return
    out.mkdir(parents=True, exist_ok=False)
    data = derive(source)
    detail = verify(source, data, provider)
    target.write_bytes(data)
    target.chmod(0o600)
    # A new byte copy, never a symlink or hardlink, in this new private data
    # directory. It is not staged to any device or made executable here.
    fd = os.open(alias, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(provider)
    info = alias.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not alias.is_symlink()
    assert alias.read_bytes() == provider and alias.parent == target.parent
    bad = negatives(source, data, provider)
    results = []
    # The current dyld_info -fixups crashes with SIGTRAP on the unchanged
    # input and candidate; preserved build-v3 records this tool limitation.
    # Chained words are instead fully compared by the bounded pinned reader.
    for label, argv in [('static', ['xcrun', 'dyld_info', '-platform', '-dependents', '-imports', str(target)]),
                        ('provider-signature', ['/usr/bin/codesign', '--verify', '--strict', str(alias)]),
                        ('provider-identity', ['/usr/bin/codesign', '-d', '--verbose=4', str(alias)])]:
        r = subprocess.run(argv, capture_output=True)
        (out / (label + '.stdout')).write_bytes(r.stdout)
        (out / (label + '.stderr')).write_bytes(r.stderr)
        assert r.returncode == 0
        if label == 'provider-identity':
            values = re.findall(rb'^CDHash=([0-9a-f]{40})$', r.stderr, re.MULTILINE)
            assert values == [b'e718d5b10cdf2d472a46b006fc23729da1d157b1']
        results.append(dict(label=label, argv=argv, exit=r.returncode))
    proof = dict(schema='Original27 VZ single maxCPU leaf route inert v1', builder=m.pin(pathlib.Path(__file__)),
                 reader=m.pin(READER), source=m.pin(SOURCE), binary=m.pin(target), provider=m.pin(PROVIDER),
                 providerAlias=m.pin(alias), providerCDHash='e718d5b10cdf2d472a46b006fc23729da1d157b1',
                 verification=detail, staticTools=results, negativeControlCount=len(bad),
                 deviceOperations=0, originalVZLoaded=False, originalVMMExecuted=False, guestInstructions=0,
                 providerIOSExecuted=False, awaitingActualIOSHelper=True, signingCalls=0, full27Backend=False)
    (out / 'negative-controls.json').write_text(json.dumps(bad, indent=2) + '\n')
    (out / 'candidate.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(dict(passed=True, binary=m.pin(target), candidate=m.pin(out / 'candidate.json'), negativeControls=len(bad))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    run(args.out.resolve(), args.check)
