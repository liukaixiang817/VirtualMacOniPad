#!/usr/bin/env python3
"""Plan trace commands only after the actual .09 header transaction is verified."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('current_stock', HERE/'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
from current_hid_extra_three_capture_v1 import mapping


def main():
    n = p.NODE
    out = n/'ipad-current-hid-trace-command-prefix-plan-v1'
    assert not out.exists()
    cap = n/'ipad-current-cache-trace-header-readonly-v1'
    rp = cap/'receipt.json'
    receipt = json.loads(rp.read_bytes())
    assert p.pin(rp)['sha256'] == 'e9850ebac2e757e76d63d2837537f75539faadab0c2fd0782f000792228220a1'
    assert receipt['transportExit'] == 0 and receipt['requestedBytes'] == 8192
    assert receipt['mainAndMemberHeadersGuardedBeforeAndAfter'] and receipt['currentTraceMemberIdentityProven']
    assert all(receipt[key] == 0 for key in ('deviceWrites', 'nativeCPUCalls', 'nativeVMCalls', 'newFrameworksLoaded'))
    pins = [p.pin(rp)]
    for key in ('reader', 'manifest', 'script', 'inputPins', 'stdout', 'stderr', 'headers'):
        pin = receipt[key]
        assert p.pin(Path(pin['path'])) == pin
        pins.append(pin)
    hp = cap/'headers.json'
    headers = json.loads(hp.read_bytes())
    assert len(headers['headers']) == 14
    oldhp = n/'ipad-current-cache-objc-linkedit-header-v1/headers.json'
    old = json.loads(oldhp.read_bytes())
    assert headers['headers'][:-1] == old['headers']
    member = headers['headers'][-1]
    assert member['name'] == '09' and member['UUID'] == 'a0382d94e343309f9c547d8ac8bb852b'
    output = (cap/'stdout').read_bytes()
    assert output.endswith(b'FINAL_MAIN_AND_MEMBER09_HEADERS_MATCH\n')
    manifest = json.loads((cap/'manifest.json').read_bytes())
    frames = re.findall(rb'BEGIN_BASE64 (main|09)\n(.*?)\nEND_BASE64 \1\n', output, re.S)
    assert len(frames) == 2
    for row, (name, encoded) in zip(manifest['fixedFiles'], frames):
        raw = base64.b64decode(re.sub(rb'\s', b'', encoded), validate=True)
        assert row['name'].encode() == name and len(raw) == 4096
        assert raw == (cap/(row['name']+'-header.bin')).read_bytes()
        assert raw[88:104].hex() == row['expectedUUID']
        assert hashlib.sha256(raw).hexdigest() == row['expectedHeaderSHA256']
        actual = next(x for x in headers['headers'] if x['name'] == row['name'])
        at, count = struct.unpack_from('<II', raw, 16)
        assert actual['maps'] == [dict(zip(('address', 'size', 'fileOffset', 'maxProt', 'initProt'),
                         struct.unpack_from('<3Q2I', raw, at+32*i))) for i in range(count)]
        pins.append(p.pin(cap/(row['name']+'-header.bin')))
    plan = n/'ipad-current-hid-trace-member-header-plan-v1'
    for pin in json.loads((plan/'freeze.json').read_bytes())['files']:
        assert p.pin(Path(pin['path'])) == pin
        pins.append(pin)
    derivation = json.loads((plan/'derivation.json').read_bytes())
    image = derivation['actualTraceInventoryRow']
    mapped = mapping(headers, image['address'], 4096)
    assert mapped['cache'] == '09' and mapped['offset'] >= 4096
    row = dict(name='system-trace-commands-prefix', **mapped)
    out.mkdir(mode=0o700)
    p.save(out/'request.json', dict(ranges=[row]))
    p.save(out/'derivation.json', dict(schema='Actual guarded current trace command prefix request v1',
        currentHeaders=p.pin(hp), actualMemberHeaderReceipt=p.pin(rp), actualImage=image,
        actualMainSubcacheRecord=derivation['actualMainRecord'], exactCurrentMapping=mapped,
        requestedRanges=1, requestedBytes=4096, priorThirteenHeadersPreserved=True,
        readerMustBeNewFixedWhitelistVersionAdding09Only=True, deviceOperations=0,
        nativeCPUCalls=0, frameworkLoads=0, actualTraceCommandsAndExportsNotYetCaptured=True,
        full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(path) for path in [oldhp, plan/'freeze.json', Path(__file__),
                                    out/'request.json', out/'derivation.json', out/'source.py']]
    p.save(out/'freeze.json', dict(files=list({row['path']: row for row in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'), freeze=p.pin(out/'freeze.json'), range=row)))


if __name__ == '__main__':
    main()
