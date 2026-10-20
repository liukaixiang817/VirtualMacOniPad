#!/usr/bin/env python3
"""Derive three current leaf export requests from complete actual command prefixes."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('current_stock', HERE/'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
from current_hid_extra_three_capture_v1 import commands, mapping


def main():
    n = p.NODE
    out = n/'ipad-current-hid-system-three-exports-plan-v1'
    assert not out.exists()
    plan_dir = n/'ipad-current-hid-system-three-command-prefixes-plan-v2'
    prior = json.loads((plan_dir/'derivation.json').read_bytes())
    pins = []
    for pin in json.loads((plan_dir/'freeze.json').read_bytes())['files']:
        assert p.pin(Path(pin['path'])) == pin
        pins.append(pin)
    hp = n/'ipad-current-cache-objc-linkedit-header-v1/headers.json'
    headers = json.loads(hp.read_bytes())
    cap = n/'ipad-current-hid-system-three-command-prefixes-readonly-v1'
    receipt = s.checked_capture(cap, plan_dir/'request.json', hp)
    assert receipt['readerSHA256'] == p.pin(cap/'reader-source.py')['sha256'] == prior['reader']['sha256']
    assert prior['currentHeaders'] == p.pin(hp)
    plans, proofs, negatives = [], [], []
    binaries = []
    for declared, captured in zip(prior['proposedLeaves'], receipt['ranges']):
        prefix = Path(captured['path'])
        raw = prefix.read_bytes()
        assert len(raw) == 4096 and captured['name'] == declared['range']['name']
        extent = 32 + struct.unpack_from('<I', raw, 20)[0]
        assert 32 < extent <= 4096
        complete = raw[:extent]
        parsed = commands(p, complete, declared['image'])
        assert {key: captured[key] for key in ('cache', 'offset', 'length')} == mapping(headers, parsed['text']['address'], 4096)
        mapped = mapping(headers, parsed['exportVA'], parsed['exportLength'])
        stem = captured['name'].removesuffix('-commands-prefix')
        row = dict(name=stem+'-exports', **mapped)
        assert mapped['cache'] == '44-linkedit' and mapped['offset'] >= 4096
        plans.append(row)
        cp = out/(stem+'-commands.bin')
        binaries.append((cp, complete))
        proofs.append(dict(image=declared['image'], actualLibSystemReexport=declared['actualLibSystemReexport'],
                           completeActualCommands=dict(path=str(cp), bytes=len(complete)), actualPrefix=p.pin(prefix),
                           actualDependencies=parsed['dependencies'], actualExportVA=parsed['exportVA'],
                           actualExportOffset=parsed['exportOffset'], actualExportLength=parsed['exportLength'],
                           request=row, potentialStrongQueries=declared['potentialStrongQueries'],
                           leafExportsCaptured=False, leafDefinitionProven=False))
        for label, bad in [('truncated commands', complete[:-1]), ('added command bytes', complete+b'\0')]:
            try:
                commands(p, bad, declared['image'])
            except (AssertionError, ValueError):
                negatives.append(dict(owner=parsed['path'], name=label, rejected=True))
            else:
                raise AssertionError('accepted malformed actual full commands')
    assert len(plans) == 3 and sum(x['length'] for x in plans) <= 4*1024*1024
    out.mkdir(mode=0o700)
    for cp, raw in binaries:
        cp.write_bytes(raw)
    for proof in proofs:
        proof['completeActualCommands'] = p.pin(Path(proof['completeActualCommands']['path']))
    p.save(out/'request.json', dict(ranges=plans))
    p.save(out/'derivation.json', dict(schema='Three actual current libSystem leaf export requests v1',
        currentHeaders=p.pin(hp), reader=prior['reader'], actualPrefixReceipt=p.pin(cap/'receipt.json'),
        originalCommandPrefixPlan=p.pin(plan_dir/'derivation.json'), definitions=proofs,
        deferredTraceLeaf=prior['deferredLeaves'], requestedRanges=3,
        requestedBytes=sum(x['length'] for x in plans), negativeControls=negatives,
        deviceOperations=0, nativeCPUCalls=0, frameworkLoads=0, actualLeafDefinitionsNotYetProven=True,
        full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(path) for path in [plan_dir/'freeze.json', hp, Path(__file__), out/'source.py',
                out/'request.json', out/'derivation.json']+[cap/name for name in
                ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py')]+
                [Path(row['path']) for row in receipt['ranges']]+[cp for cp, _ in binaries]]
    unique = {}
    for pin in pins:
        if pin['path'] in unique:
            assert unique[pin['path']] == pin
        unique[pin['path']] = pin
    p.save(out/'freeze.json', dict(files=list(unique.values()), deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'), freeze=p.pin(out/'freeze.json'), ranges=plans,
                          requestedBytes=sum(x['length'] for x in plans))))


if __name__ == '__main__':
    main()
