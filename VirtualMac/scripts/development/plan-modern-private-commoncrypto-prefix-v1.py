#!/usr/bin/env python3
"""Plan one real libSystem commonCrypto leaf prefix, with no device access."""
import importlib.util
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('commoncrypto_frontier', HERE/'audit-modern-private-declarations-v2.py')
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
p, N = d.p, d.N
from current_hid_extra_three_capture_v1 import inventory, mapping


def main():
    out = N/'ipad-current-private-commoncrypto-command-prefix-plan-v1'; assert not out.exists()
    images, pins = d.current_images()
    hp = N/'ipad-current-cache-trace-header-readonly-v1/headers.json'
    headers = d.strict_json(hp); assert len(headers['headers']) == 14
    archive = N.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail = N/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    table_path = N/'ipad-current-cache-hid-extra-inventory-v1/current-images.json'
    rows = inventory(archive.read_bytes()[:4096], tail.read_bytes(), headers)
    assert rows == d.strict_json(table_path)
    path = '/usr/lib/system/libcommonCrypto.dylib'
    actual = [x for x in rows if x['path'] == path]; assert len(actual) == 1
    dependency = [x for x in images['/usr/lib/libSystem.B.dylib']['dependencies'] if x['path'] == path]
    assert len(dependency) == 1 and dependency[0]['command'] == 0x8000001f
    declaration_path = N/'current-private-scoped-declarations-readonly-v2/audit.json'
    pins += d.original_freeze(declaration_path.parent/'freeze.json')
    report = d.strict_json(declaration_path)
    requested = []
    for name, symbol in [('EfiSupport27', '_CNCRC'), ('VM27NativeRTTICompat', '_CC_SHA256')]:
        provider = next(x for x in report['declaredProviderImports'] if x['name'] == name)
        item = next(x for x in provider['imports'] if x['symbol'] == symbol)
        assert item['dependency'] == '/usr/lib/libSystem.B.dylib'
        assert item['proof']['status'] == 'ownerHasNoDefinitionReexportsUnverified'
        requested.append(dict(provider=name, actualStrongImport=item,
                              candidate=next(x['candidate'] for x in report['providers'] if x['name'] == name)))
    request = dict(name='private-commoncrypto-commands-prefix', **mapping(headers, actual[0]['address'], 4096))
    assert request['offset'] >= 4096 and request['cache'] in {x['name'] for x in headers['headers']}
    reader = HERE/'read-ipad-current-cache-ranges-readonly-v9.py'
    assert p.pin(reader)['sha256'] == 'c6cea43fd413a7823ad7c38e7844617834bc1e1f399ef128637e3266cb4a4b7b'
    out.mkdir(mode=0o700)
    p.save(out/'request.json', dict(ranges=[request]))
    p.save(out/'derivation.json', dict(schema='Actual libSystem commonCrypto leaf prefix request v1',
        headers=p.pin(hp), reader=p.pin(reader), actualInventory=p.pin(table_path), actualImage=actual[0],
        actualLibSystemReexport=dependency[0], requestedPrivateImports=requested,
        request=request, requestedRanges=1, requestedBytes=4096,
        actualCommonCryptoExportsCaptured=False, requestedSymbolsDefined=False,
        particularLeafFunctionABIProven=False, deviceOperations=0, frameworkLoads=0,
        nativeCPUCalls=0, full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(x) for x in (Path(__file__), hp, archive, tail, table_path, reader,
        declaration_path, out/'request.json', out/'derivation.json', out/'source.py')]
    dedup = {x['path']:x for x in pins}; assert all(dedup[x['path']] == x for x in pins)
    p.save(out/'freeze.json', dict(files=list(dedup.values()), deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'), derivation=p.pin(out/'derivation.json'),
                          freeze=p.pin(out/'freeze.json'), range=request)))


if __name__ == '__main__': main()
