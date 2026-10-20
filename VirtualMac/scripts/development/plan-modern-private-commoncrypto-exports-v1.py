#!/usr/bin/env python3
"""Derive commonCrypto's bounded export read from actual complete commands."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('commoncrypto_prefix', HERE/'plan-modern-private-commoncrypto-prefix-v1.py')
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
d, p, N = t.d, t.p, t.N
from current_hid_extra_three_capture_v1 import commands, mapping


def main():
    out = N/'ipad-current-private-commoncrypto-exports-plan-v1'; assert not out.exists()
    before = N/'ipad-current-private-commoncrypto-command-prefix-plan-v1'
    capture = N/'ipad-current-private-commoncrypto-command-prefix-readonly-v1'
    pins = d.original_freeze(before/'freeze.json')
    declaration = d.strict_json(before/'derivation.json')
    hp = Path(declaration['headers']['path']); assert p.pin(hp) == declaration['headers']
    receipt = d.f.s.checked_capture(capture, before/'request.json', hp)
    assert receipt['readerSHA256'] == declaration['reader']['sha256'] == p.pin(capture/'reader-source.py')['sha256']
    prefix = capture/'private-commoncrypto-commands-prefix.bin'
    raw = prefix.read_bytes(); size = 32+struct.unpack_from('<I', raw, 20)[0]
    assert len(raw) == 4096 and size == 2368
    raw = raw[:size]; parsed = commands(p, raw, declaration['actualImage'])
    headers = d.strict_json(hp)
    assert mapping(headers, declaration['actualImage']['address'],4096) == {
        k:receipt['ranges'][0][k] for k in ('cache','offset','length')}
    request = dict(name='private-commoncrypto-exports', **mapping(headers, parsed['exportVA'],parsed['exportLength']))
    assert request['cache'] == '44-linkedit' and request['offset'] >= 4096
    assert 0 < request['length'] <= 2*1024*1024
    out.mkdir(mode=0o700)
    cp = out/'private-commoncrypto-commands.bin'; cp.write_bytes(raw); cp.chmod(0o600)
    p.save(out/'request.json',dict(ranges=[request]))
    p.save(out/'derivation.json',dict(schema='Current actual commonCrypto complete-command export request v1',
        currentHeaders=p.pin(hp), reader=declaration['reader'], actualImage=declaration['actualImage'],
        actualLibSystemReexport=declaration['actualLibSystemReexport'],
        actualPrefix=p.pin(prefix), actualCompleteCommands=p.pin(cp), actualParsedCommands=parsed,
        currentActualPrefixReceipt=p.pin(capture/'receipt.json'), requestedPrivateImports=declaration['requestedPrivateImports'],
        request=request, requestedRanges=1,requestedBytes=request['length'], exportsAlreadyRead=False,
        _CNCRCDefined=False,_CC_SHA256Defined=False, deviceOperations=0,nativeCPUCalls=0,frameworkLoads=0,full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(x) for x in (Path(__file__),hp,prefix,cp,before/'request.json',before/'derivation.json',
        capture/'receipt.json',capture/'manifest.json',capture/'script.sh',capture/'stdout',capture/'stderr',
        capture/'reader-source.py',out/'request.json',out/'derivation.json',out/'source.py')]
    dedup = {x['path']:x for x in pins}; assert all(dedup[x['path']] == x for x in pins)
    p.save(out/'freeze.json',dict(files=list(dedup.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),derivation=p.pin(out/'derivation.json'),
        freeze=p.pin(out/'freeze.json'),range=request)))


if __name__ == '__main__': main()
