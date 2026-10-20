"""Read saved DI2 load-only observations; never loads code or touches a device."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[3]
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BUILD = N / 'diskimages2-strong-loadonly-build-v3'
REVIEW = N / 'diskimages2-strong-loadonly-root-review-v1'
H = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def contract():
    assert H(BUILD / 'candidate.json') == '3ea4e655da484fa0853cc5752f38fe64072b169e97193755b875ae7e84ed4daf'
    assert H(REVIEW / 'freeze.json') == '2681e06005680123cd7e43f24c3cae5cfe53641da965d7955568678bb15a75f8'
    for row in json.loads((REVIEW / 'freeze.json').read_bytes())['files']:
        p = ROOT / row['path']
        assert not p.is_symlink() and p.stat().st_size == row['bytes'] and H(p) == row['sha256']
    source = (BUILD / 'ios/diskimages227-pins.h').read_text()
    images = re.findall(r'^\{"([^"\n]+)",(\d+),\{([0-9,]+)\},"([a-f0-9]{32})"\},$', source, re.M)
    providers = re.findall(r'^\{"([^"\n]+)",(\d+),([01])\},$', source, re.M)
    classes = json.loads('[' + re.search(r'ClassNames\[5\]=\{(.*?)\};', source).group(1) + ']')
    methods = re.findall(r'^\{"([^"\n]+)","([^"\n]+)","([^"\n]+)",(0x[a-f0-9]+)\},$', source, re.M)
    assert len(images) == 11 and len(providers) == 45 and len(classes) == 5 and len(methods) == 8
    candidate = json.loads((BUILD / 'candidate.json').read_bytes())
    assert [Path(x[0]).name for x in images] == [x['name'] for x in candidate['files'][:11]]
    for image, row in zip(images, candidate['files']):
        assert int(image[1]) == row['bytes'] and bytes(map(int, image[2].split(','))).hex() == row['sha256'] and image[3] == row['UUID']
    return images, providers, classes, methods


def native_transcript(path, stderr, pid, wait):
    images, providers, classes, methods = contract()
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    assert pid > 1 and rows[0] == {'record': 'start', 'PID': pid, 'DI2APICalls': 0}
    if wait == 67:
        # dlopen did not return an image. No API or inventory followed it.
        assert len(rows) == 1
        lines = Path(stderr).read_text().splitlines(keepends=True)
        assert lines[0] == f'NATIVE_STARTED pid={pid}\n' and lines[-1] == f'NATIVE_WAIT pid={pid} exit=67\n'
        error = ''.join(lines[1:-1])
        assert error.startswith('genuine27 DI2 dlopen: ') and error.strip() != 'genuine27 DI2 dlopen:'
        assert error.count('genuine27 DI2 dlopen: ') == 1
        return dict(passed=False, diagnosticVerified=True, genuineDI2Loaded=False, DI2APICalls=0,
                    directChildPID=pid, observedWaitExit=wait, loaderError=error.strip(), full27Backend=False)
    assert wait == 0
    assert Path(stderr).read_text() == f'NATIVE_STARTED pid={pid}\nNATIVE_WAIT pid={pid} exit=0\n'
    expected = ['start'] + ['identity'] * 45 + ['identity', 'class'] * 5 + ['identity', 'method'] * 8 + ['summary']
    assert [row['record'] for row in rows] == expected and len(rows) == 73

    def identity(row, image, rva=None):
        assert set(row) == {'record', 'UUID', 'path', 'RVA'}
        assert row['UUID'] == image[3]
        assert row['path'] == '/private' + image[0]
        assert isinstance(row['RVA'], str) and re.fullmatch(r'0x[0-9a-f]+', row['RVA'])
        actual = int(row['RVA'], 16)
        assert 0 < actual < int(image[1])
        if rva is not None:
            assert actual == rva

    for row, provider in zip(rows[1:46], providers):
        identity(row, images[int(provider[1])])
    index = 46
    for name in classes:
        identity(rows[index], images[10])
        assert rows[index + 1] == {'record': 'class', 'name': name, 'actualPrivateDI2Class': True}
        index += 2
    for cls, selector, encoding, rva in methods:
        identity(rows[index], images[10], int(rva, 16))
        assert rows[index + 1] == {'record': 'method', 'class': cls, 'selector': selector,
                                   'actualOriginalRVA': rva, 'calls': 0}
        index += 2
    assert rows[index] == {'record': 'summary', 'PID': pid, 'genuine27UUID': images[10][3],
                           'privateProviders': 45, 'classes': 5, 'methods': 8,
                           'DI2APICalls': 0, 'diskVMGPUCalls': 0, 'passed': True}
    return dict(passed=True, diagnosticVerified=True, genuineDI2Loaded=True, genuineUUID=images[10][3],
                privateProviderIdentities=45, genuineClasses=5, genuineMethodIdentities=8, DI2APICalls=0,
                directChildPID=pid, observedWaitExit=wait, RAWReadWriteVerified=False, full27Backend=False)
