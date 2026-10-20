"""Bind the new unsigned diagnostic to unchanged current system definitions."""
from pathlib import Path
import hashlib, json, struct

S = Path(__file__).resolve().parent
N = S.parents[2] / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D = N / 'cpu-owned-brk-device-unsigned-local-v6'
H = N / 'cpu-owned-brk-device-host-faults-v5'
P = N / 'cpu-owned-brk-current-definitions-binding-v2'

def pin(path):
    p = Path(path).resolve()
    b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')

def imports(path):
    b = Path(path).read_bytes()
    if struct.unpack_from('<I', b)[0] != 0xfeedfacf:
        raise ValueError('thin64 image required')
    at = 32
    paths = []
    fixup = None
    for _ in range(struct.unpack_from('<I', b, 16)[0]):
        command, size = struct.unpack_from('<II', b, at)
        if command == 12:
            off = struct.unpack_from('<I', b, at+8)[0]
            paths.append(b[at+off:at+size].split(b'\0')[0].decode())
        elif command == 0x80000034:
            if fixup is not None:
                raise ValueError('duplicate fixup command')
            fixup = struct.unpack_from('<II', b, at+8)
        at += size
    if not fixup:
        raise ValueError('actual chained import table required')
    off, length = fixup
    version, _, table, names, count, fmt, compressed = struct.unpack_from('<7I', b, off)
    if version != 0 or compressed != 0 or fmt not in (1, 2, 3):
        raise ValueError('unsupported actual import format')
    rows = []
    for i in range(count):
        pos = off + table + i * {1:4, 2:8, 3:16}[fmt]
        if fmt in (1, 2):
            word = struct.unpack_from('<I', b, pos)[0]
            ordinal, weak, name = word & 255, bool((word >> 8) & 1), word >> 9
            addend = 0 if fmt == 1 else struct.unpack_from('<i', b, pos+4)[0]
        else:
            word, addend = struct.unpack_from('<Qq', b, pos)
            ordinal, weak, name = word & 65535, bool((word >> 16) & 1), word >> 32
        if not 1 <= ordinal <= len(paths):
            raise ValueError('ordinary exact image ordinal required')
        start = off + names + name
        end = b.index(0, start, off+length)
        rows.append(dict(index=i, symbol=b[start:end].decode(), ordinal=ordinal,
                         path=paths[ordinal-1], weak=weak, addend=addend))
    return rows

def main():
    out = N / 'cpu-owned-brk-current-definitions-binding-v6'
    out.mkdir(exist_ok=False)
    rows = {}
    def exact(row):
        if pin(row['path']) != {k:row[k] for k in ('path', 'bytes', 'sha256')}:
            raise ValueError('frozen input changed: '+row['path'])
        rows[row['path']] = {k:row[k] for k in ('path', 'bytes', 'sha256')}
    parent = json.loads((P / 'binding.json').read_bytes())
    candidate = json.loads((D / 'candidate.json').read_bytes())
    for row in json.loads((P / 'freeze.json').read_bytes())['files']:
        exact(row)
    actual = imports(candidate['binary']['path'])
    if actual != parent['actualImports'] or len(actual) != 53:
        raise ValueError('new actual import table differs from current definition proof')
    binding = dict(schema='Actual unchanged53 import definitions bind BRK v6 CPU rlimit and explicit debug control correction',
        candidate=pin(D/'candidate.json'), provider=candidate['binary'], actualImports=actual,
        parentBinding=pin(P/'binding.json'), parentFreeze=pin(P/'freeze.json'),
        all53ActualEntriesExactlyUnchanged=True, all53CurrentDefinitionsJoined=True,
        inheritedDefinitionEvidenceOnly=True, freshDeviceDefinitionRead=False,
        deviceOperations=0, nativeOperationsExecuted=0, full27Backend=False)
    save(out/'binding.json', binding)
    for folder in (D, H):
        for p in folder.iterdir():
            if p.is_file() and p.name != 'freeze.json': rows[str(p.resolve())] = pin(p)
    for p in (P/'binding.json', P/'freeze.json', Path(__file__),
              S/'finalize-cpu-owned-brk-device-v6.py'):
        rows[str(p.resolve())] = pin(p)
    for row in candidate['inputs'] + json.loads((H/'host-results.json').read_bytes())['inputs']:
        exact(row)
    save(out/'freeze.json', dict(files=list(rows.values()), deviceOperations=0))
    final = dict(schema='BRK v6 corrected finite diagnostic source binding',
        sourceFinalization=pin(D/'source-finalization.json'), currentDefinitions=pin(out/'binding.json'),
        sourceCandidate=pin(D/'candidate.json'), binary=candidate['binary'],
        normalFaultModes=12, sanitizedFaultModes=12, requiredCPULimitInfinity=True,
        externalWallSeconds=20, native9Maximum=1, oldFrozenV2Preserved=True,oldFrozenV3Preserved=True,requiresActualDebugTrapControl2=True,
        providerSigned=False, deviceOperations=0, nativeOperationsExecuted=0,
        guestBooted=False, full27Backend=False)
    save(D/'root-finalization.json', final)
    rows[str((D/'root-finalization.json').resolve())] = pin(D/'root-finalization.json')
    rows[str((out/'binding.json').resolve())] = pin(out/'binding.json')
    rows[str((out/'freeze.json').resolve())] = pin(out/'freeze.json')
    save(D/'freeze.json', dict(files=list(rows.values()), deviceOperations=0))
    print(json.dumps(dict(finalization=pin(D/'root-finalization.json'), freeze=pin(D/'freeze.json'), pins=len(rows))))

if __name__ == '__main__':
    main()
