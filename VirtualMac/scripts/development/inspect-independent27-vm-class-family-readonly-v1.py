#!/usr/bin/env python3
"""HOST-only bounded original VZ class-family metadata inspection."""
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'

def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def main():
    product = N / 'independent27-signed-runtime-uikit-filter-product-v10-attempt1/candidate.json'
    candidate = json.loads(product.read_bytes())
    path = pathlib.Path(candidate['runtimeRoot']) / 'parent-flat/VZ27.dylib'
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('vm_class_family_readonly_v1', reader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    raw = path.read_bytes()
    image = module.MachO(raw)
    assert image.uuid == '418efc4809d93606918eb6f95baeffdc'

    def pointer(va):
        word = struct.unpack_from('<Q', raw, image.file(va))[0]
        if not word:
            return None
        if word >> 62 & 1:
            return dict(importName=image.imports[word & 0xffffff]['name'], rawWord=hex(word))
        return image.base + ((word & 0xffffffff) if word >> 63 else word & ((1 << 43) - 1))

    def string(va):
        at = image.file(va)
        return raw[at:raw.index(0, at)].decode()

    section = next(row for row in image.sections if row['name'] == '__objc_classlist')
    assert section['size'] % 8 == 0 and section['size'] // 8 < 1024
    classes = []
    for at in range(section['va'], section['va'] + section['size'], 8):
        cls = pointer(at)
        assert isinstance(cls, int)
        ro = pointer(cls + 32) & ~7
        _, start, size = struct.unpack_from('<III', raw, image.file(ro))
        classes.append(dict(name=string(pointer(ro + 24)), classRVA=cls - image.base,
            classRORVA=ro - image.base, rawInstanceStart=start, rawInstanceSize=size,
            alignedLP64InstanceSize=(size + 7) & ~7, superclassPointer=pointer(cls + 8),
            classBytes=raw[image.file(cls):image.file(cls) + 40].hex(),
            classROBytes=raw[image.file(ro):image.file(ro) + 72].hex()))
    by_address = {image.base + row['classRVA']: row for row in classes}
    assert len(by_address) == len(classes)
    for row in classes:
        parent = row['superclassPointer']
        row['superclassName'] = by_address[parent]['name'] if isinstance(parent, int) and parent in by_address else (
            parent.get('importName') if isinstance(parent, dict) else None)

    def ancestors(row):
        seen, names = set(), []
        while row:
            assert row['classRVA'] not in seen
            seen.add(row['classRVA'])
            names.append(row['name'])
            parent = row['superclassPointer']
            row = by_address.get(parent) if isinstance(parent, int) else None
        return names

    family = [row for row in classes if 'VZVirtualMachine' in ancestors(row)]
    assert len(family) == 1 and family[0]['name'] == 'VZVirtualMachine'
    assert family[0]['alignedLP64InstanceSize'] == 384
    assert family[0]['classRVA'] == image.exports['_OBJC_CLASS_$_VZVirtualMachine']['address']
    assert family[0]['superclassName'] == '_OBJC_CLASS_$_NSObject'
    out = N / 'independent27-original-vm-class-family-readonly-v1-attempt1'
    out.mkdir(mode=0o700)
    report = dict(schema='Finite HOST original VM class-family metadata v1', product=pin(product),
        originalVZ=pin(path), UUID=image.uuid, actualDefinedClassCount=len(classes),
        actualDefinedVMClassFamily=family,
        relatedDefinedClassNames=[row['name'] for row in classes if 'VirtualMachine' in row['name']],
        genuineUIKitFactory=pin(R / 'VirtualMac/vz/host/vm27_uikit_guest_display_v1.mm'),
        inheritedRuntimeExactClassGate=pin(R / 'VirtualMac/vz/host/vm27_independent_app_runtime_v2.m'),
        staticUIKitVMSubclassDefinitionFound=False, actualDynamicObjectClassNotObserved=True,
        arbitrarySubclassAcceptanceAuthorized=False, dynamicKVOIdentityProved=False,
        sourceFinding='The factory calls the original VZVirtualMachine alloc/queue initializer. Its image has no static subclass of that class. A runtime object_getClass mismatch still needs actual identity diagnostics; it cannot justify guessing a subclass name.',
        nativeCalls=0, deviceOperations=0, runtimeExecuted=False)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    rows = [pin(__file__), pin(reader), pin(product), pin(path), report['genuineUIKitFactory'],
        report['inheritedRuntimeExactClassGate'], pin(out / 'report.json')]
    (out / 'freeze.json').write_text(json.dumps(dict(files=rows, deviceOperations=0), indent=2) + '\n')
    print(json.dumps(dict(report=pin(out / 'report.json'), freeze=pin(out / 'freeze.json'))))

if __name__ == '__main__':
    main()
