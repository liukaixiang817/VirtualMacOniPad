#!/usr/bin/env python3
"""Derive two exact TypeLayout reads from actual captured arm64e slide3 pointers."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pod_layout_current', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p


def auth_slot(raw, add, discriminator):
    assert raw >> 63 == 1 and ((raw >> 49) & 3) == 2
    assert ((raw >> 48) & 1) == 1 and ((raw >> 32) & 0xffff) == discriminator
    return dict(raw=hex(raw), actualTarget=add + (raw & 0xffffffff), key=2,
                diversity=discriminator, addressDiversity=True, nextBytes=((raw >> 51) & 0x7ff) * 8,
                schema='actual arm64e cache slide3 authenticated rebase')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    headers = p.NODE / 'ipad-current-cache-pod-leaf-headers-v3/headers.json'
    manifest = p.NODE / 'ipad-current-hid-pod-native-metadata-plan-v3/request.json'
    capture = p.NODE / 'ipad-current-hid-pod-native-metadata-readonly-v1'
    s.checked_capture(capture, manifest, headers)
    heads = json.loads(headers.read_bytes())
    assert heads['mainUUID'] == '1995ea169d0a33a0b78962cf99891168' and len(heads['headers']) == 10
    physical = next(x for x in heads['headers'] if x['name'] == '27-data')
    assert physical['UUID'] == '08193a3ab05d3ab2a931a09d2a1dc98a' and physical['sha256'] == '8276c3e17b75e5ebd24a7b5f524ebc23df555f10459f6154466e2c80687066a1'
    slide_file = capture / 'native-metadata-mapping-slide-header.bin'
    version, page_size, page_count, padding, auth_add = struct.unpack('<4IQ', slide_file.read_bytes())
    assert version == 3 and page_size == 4096 and page_count == 9328 and padding == 0
    # auth_add is taken from the actual captured slide3 header, never inferred
    # from the image or a historical cache. The equality is a checked pin.
    assert auth_add == 0x180000000
    metadata_map = next(x for x in physical['maps'] if x['address'] <= 0x1de611370 < x['address'] + x['size'])
    assert page_count == metadata_map['size'] // page_size
    records, requests, inputs = [], [], [Path(__file__), Path(s.__file__), headers, manifest, slide_file]
    for name, address in (('foundation-uuid', 0x1de611370), ('swiftcore-uint64', 0x1de5e6b50)):
        source = capture / (name + '-metadata.bin')
        pointer, kind, descriptor = struct.unpack('<3Q', source.read_bytes())
        assert kind == 0x200
        vwt = auth_slot(pointer, auth_add, 0x2e3f)
        context = auth_slot(descriptor, auth_add, 0xae86)
        assert vwt['nextBytes'] == 16
        layout = vwt['actualTarget'] + 64
        matches = [(row, m) for row in heads['headers'] for m in row['maps']
                   if m['address'] <= layout and layout + 24 <= m['address'] + m['size']]
        assert len(matches) == 1
        row, mapping = matches[0]
        offset = mapping['fileOffset'] + layout - mapping['address']
        assert row['name'] == '27-data' and offset >= 4096
        requests.append(dict(name=name + '-type-layout', cache=row['name'], offset=offset, length=24))
        records.append(dict(name=name, actualMetadataVA=address, actualMetadata=p.pin(source), actualVWTRebase=vwt,
                            actualDescriptorRebase=context, typeLayoutVA=layout, typeLayoutBytes=24,
                            currentEnclosingMap=mapping, currentCacheName=row['name'], typeLayoutFileOffset=offset,
                            currentTypeLayoutBytesNotYetCaptured=True))
        inputs.append(source)
    request = out / 'request.json'
    p.save(request, dict(schema='bounded-current-iPad-POD-native-type-layout-v1', ranges=requests))
    p.save(out / 'derivation.json', dict(schema='Actual current captured slide3 metadata to TypeLayout request v1',
        currentHeaders=p.pin(headers), metadataCaptureReceipt=p.pin(capture / 'receipt.json'),
        actualSlideHeader=p.pin(slide_file), actualSlideVersion=version, actualPageSize=page_size,
        actualPageCount=page_count, actualAuthValueAdd=auth_add, records=records, request=p.pin(request),
        requestedRanges=2, requestedBytes=48, archivePointersUsed=False, deviceOperations=0, nativeExecuted=False,
        metadataLayoutFieldsVerified=False, candidateReadyForNativeLoading=False))
    inputs.extend(capture / name for name in ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py'))
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in inputs + [request, out / 'derivation.json']],
        deviceOperations=0, nativeExecuted=False))
    print(json.dumps(dict(request=p.pin(request), ranges=requests, targets=[r['actualVWTRebase']['actualTarget'] for r in records])))


if __name__ == '__main__':
    main()
