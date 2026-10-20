"""Prepare a finite native sandbox code read; never contact the iPad."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUT = NODE / 'ipad-current-native-sandbox-code-plan-v1-attempt1'
READER = ROOT / 'VirtualMac/scripts/development/read-ipad-current-cache-ranges-readonly-v11.py'
HEADERS = NODE / 'ipad-current-mediakit-member31-header-readonly-v1/headers.json'
HELPER = ROOT / 'DeviceDiagnostics/2026-10-02-ssh-steam-repair/remote.py'
ASKPASS = Path('/private/tmp/virtualmac-ipad-tools/ssh-askpass')
READER_SHA = '742595c2ecd4bf119ba454c17a3e135c7ea4e546336f675dc1eccf32534ddfef'
HEADERS_SHA = 'ea2d4bda25e393127e3f004e9689d6cd42ace179ffda66374ab9af39f8260fb0'
HELPER_SHA = '29a8d0241704440152fb734cf78cf0b0536c30524ab121da483941777b215424'
ASKPASS_SHA = '6ac7ae3ea37b8d21a21155dfee7abc592e840fa471f8e39a4c79b9ea045ab929'


def pin(path):
    body = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def fixed_script(reader, headers, rows):
    """Evaluate only the pinned reader's pure shell construction statements."""
    assert pin(reader)['sha256'] == READER_SHA
    tree = ast.parse(reader.read_text())
    assigns = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
               if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
               and n.targets[0].id == 'BASE'}
    namespace = dict(re=re, rows=rows, pinned={r['name']: r for r in headers['headers']}, **assigns)
    files_node = next(n for n in tree.body if isinstance(n, ast.Assign)
                      and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'FILES')
    exec(compile(ast.Module(body=[files_node], type_ignores=[]), str(reader), 'exec'), namespace)
    assert set(namespace['FILES']) == set(namespace['pinned'])
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    start = next(i for i, n in enumerate(main.body) if isinstance(n, ast.Assign)
                 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'script')
    end = next(i for i, n in enumerate(main.body) if i > start and isinstance(n, ast.Expr)
               and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute)
               and isinstance(n.value.func.value, ast.Name) and n.value.func.value.id == 'subprocess')
    statements = main.body[start:end]
    assert len(statements) == 6
    assert all(isinstance(n, (ast.Assign, ast.FunctionDef, ast.AugAssign, ast.For)) for n in statements)
    exec(compile(ast.Module(body=statements, type_ignores=[]), str(reader), 'exec'), namespace)
    return namespace['script'].encode()


def image_commands(path):
    import struct
    data = path.read_bytes()
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    count, length = struct.unpack_from('<II', data, 16)
    assert 32 + length <= len(data)
    at = 32
    segments, identities, uuids = [], [], []
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, at)
        assert size >= 8 and size % 8 == 0 and at + size <= 32 + length
        if command == 0x19:
            segment = struct.unpack_from('<II16sQQQQiiII', data, at)
            name = segment[2].split(b'\0')[0].decode()
            sections = []
            for i in range(segment[9]):
                section = struct.unpack_from('<16s16sQQIIIIIIII', data, at + 72 + i * 80)
                sections.append(dict(name=section[0].split(b'\0')[0].decode(),
                                     va=section[2], bytes=section[3], fileOffset=section[4], flags=section[8]))
            segments.append(dict(name=name, va=segment[3], bytes=segment[4],
                                 fileOffset=segment[5], fileBytes=segment[6], sections=sections))
        elif command == 0x1b:
            uuids.append(data[at + 8:at + 24].hex())
        elif command == 13:
            offset = struct.unpack_from('<I', data, at + 8)[0]
            identities.append(data[at + offset:at + size].split(b'\0')[0].decode())
        at += size
    assert at == 32 + length and len(identities) == len(uuids) == 1
    return dict(path=identities[0], UUID=uuids[0], segments=segments)


def mapped(headers, va, size):
    matches = [(row, part) for row in headers['headers'] for part in row['maps']
               if part['address'] <= va and va + size <= part['address'] + part['size']]
    assert len(matches) == 1
    row, part = matches[0]
    return dict(cache=row['name'], offset=part['fileOffset'] + va - part['address'], length=size)


def main():
    assert pin(READER)['sha256'] == READER_SHA and pin(HEADERS)['sha256'] == HEADERS_SHA
    assert pin(HELPER)['sha256'] == HELPER_SHA and pin(ASKPASS)['sha256'] == ASKPASS_SHA
    headers = json.loads(HEADERS.read_bytes())
    assert headers['mainUUID'] == '1995ea169d0a33a0b78962cf99891168'
    assert headers['matchesArchivedMap'] is True and headers['deviceWrites'] == 0
    old_headers = NODE / 'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    old_rows = json.loads(old_headers.read_bytes())['headers']
    assert [r for r in headers['headers'] if r['name'] != '31'] == old_rows
    inputs = [Path(__file__), READER, HEADERS, old_headers, HELPER, ASKPASS]
    rows, images = [], []
    specifications = [
        ('system-sandbox', NODE / 'ipad-current-system-sandbox-exports-plan-v1/complete-commands/vz-system-sandbox-commands.bin',
         '/usr/lib/system/libsystem_sandbox.dylib', '140cc26b91e932f4ad75096c4e104eb0', 7838478336,
         NODE / 'ipad-current-system-sandbox-prefix-readonly-v1/receipt.json',
         NODE / 'ipad-current-system-sandbox-prefix-readonly-v1/vz-system-sandbox-prefix.bin'),
        ('sandbox-compiler', NODE / 'ipad-current-vz-remaining-stock-prefix-readonly-v1/vz-sandbox-prefix.bin',
         '/usr/lib/libsandbox.1.dylib', '41a96a45b5c23f928f64816ba6daa693', 7867781120,
         NODE / 'ipad-current-vz-remaining-stock-prefix-readonly-v1/receipt.json',
         NODE / 'ipad-current-vz-remaining-stock-prefix-readonly-v1/vz-sandbox-prefix.bin')]
    for label, source, identity, uuid, base, receipt_path, prefix in specifications:
        receipt = json.loads(receipt_path.read_bytes())
        assert receipt['transportExit'] == 0 and receipt['deviceWrites'] == 0
        assert receipt['allHeaderPinsMatchBeforeAndAfter'] is True
        captured = [r for r in receipt['ranges'] if Path(r['path']) == prefix]
        assert len(captured) == 1 and captured[0]['sha256'] == pin(prefix)['sha256']
        image = image_commands(source)
        assert image['path'] == identity and image['UUID'] == uuid
        text = next(s for s in image['segments'] if s['name'] == '__TEXT')
        assert text['va'] == base
        chosen = [s for s in image['segments'] if s['name'] in ('__TEXT', '__DATA_CONST', '__AUTH_CONST')]
        assert len(chosen) == 3
        image_rows = []
        for segment in chosen:
            assert segment['fileBytes'] == segment['bytes']
            request = dict(name=label + '-' + segment['name'].strip('_').lower().replace('_', '-'),
                           **mapped(headers, segment['va'], segment['bytes']))
            assert request['offset'] == segment['fileOffset']
            assert request['cache'] == ('25' if segment['name'] == '__TEXT' else '27-data')
            image_rows.append(dict(request=request, segment=segment,
                                  rationale=('Entire small image TEXT includes init/compile implementation, auth stubs, constants and strings'
                                             if segment['name'] == '__TEXT' else
                                             'Exact image GOT and constant-pointer slots needed to resolve external native call targets')))
            rows.append(request)
        images.append(dict(identity=image['path'], UUID=image['UUID'], imageBaseVA=base,
                           commandsSource=pin(source), actualPrefix=pin(prefix), actualPrefixReceipt=pin(receipt_path),
                           requestedSegments=image_rows))
        inputs += [source, receipt_path, prefix]
    total = sum(r['length'] for r in rows)
    assert len(rows) == 6 and total == 33412
    assert len(set(r['name'] for r in rows)) == len(rows)
    for row in rows:
        assert row['offset'] >= 4096 and 0 < row['length'] <= 20468
    OUT.mkdir(exist_ok=False)
    request = OUT / 'request.json'
    dump(request, dict(schema='Finite current native sandbox code read request v1', ranges=rows))
    script = fixed_script(READER, headers, rows)
    subprocess.run(['/bin/sh', '-n'], input=script, capture_output=True, check=True)
    (OUT / 'script.sh').write_bytes(script)
    outputs = NODE / 'ipad-current-native-sandbox-code-readonly-v1'
    assert not outputs.exists()
    fixed_inputs = list({p.resolve(): pin(p) for p in inputs}.values())
    dispatch_inputs = [pin(READER), pin(HEADERS), pin(HELPER), pin(ASKPASS), pin(request), pin(OUT / 'script.sh')]
    wrapper = '''"""Fixed one-shot readonly V11 dispatch; preparation never invokes this file."""
import getpass, hashlib, json, os, runpy, sys
from pathlib import Path
sys.dont_write_bytecode = True
FIXED = __FIXED__
READER = Path(__READER__)
HEADERS = Path(__HEADERS__)
REQUEST = Path(__REQUEST__)
OUTPUT = Path(__OUTPUT__)

def pin(path):
    body = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(body), sha256=hashlib.sha256(body).hexdigest())

def main():
    for row in FIXED:
        if pin(Path(row['path'])) != row:
            raise ValueError('Fixed readonly native sandbox capture input drift')
    if OUTPUT.exists():
        raise ValueError('Readonly capture output already exists; do not repeat this dispatch')
    password = getpass.getpass('iPad password: ')
    if not password:
        raise ValueError('Runtime authentication absent')
    environment_names = ('VIRTUALMAC_SSH_PASSWORD', 'SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE', 'DISPLAY')
    prior = {name: os.environ.get(name) for name in environment_names}
    prior_argv = sys.argv
    try:
        os.environ.update(VIRTUALMAC_SSH_PASSWORD=password,
                          SSH_ASKPASS='/private/tmp/virtualmac-ipad-tools/ssh-askpass',
                          SSH_ASKPASS_REQUIRE='force', DISPLAY='virtualmac-debug')
        sys.argv = [str(READER), '--manifest', str(REQUEST), '--headers', str(HEADERS), '--output', str(OUTPUT)]
        runpy.run_path(READER, run_name='__main__')
    finally:
        password = None
        sys.argv = prior_argv
        for name, value in prior.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

if __name__ == '__main__':
    main()
'''
    for token, value in [('__FIXED__', repr(dispatch_inputs)), ('__READER__', repr(str(READER))),
                         ('__HEADERS__', repr(str(HEADERS))), ('__REQUEST__', repr(str(request))),
                         ('__OUTPUT__', repr(str(outputs)))]:
        wrapper = wrapper.replace(token, value)
    ast.parse(wrapper)
    (OUT / 'read-once.py').write_text(wrapper)
    derivation = dict(schema='Prepared finite native sandbox code capture derivation v1',
                      deviceOperations=0, deviceWrites=0, nativeCPUCalls=0, nativeSandboxCalls=0,
                      frameworkLoads=0, newTrustCacheEntries=0, captureExecuted=False,
                      expectedMainCacheUUID=headers['mainUUID'], expectedMachine='iPad14,6', expectedOSBuild='20B101',
                      currentHeaders=pin(HEADERS), originalSeventeenHeadersPreserved=True,
                      reader=pin(READER), remoteHelper=pin(HELPER), askpass=pin(ASKPASS),
                      requestedBytes=total, requestedRanges=len(rows), actualImagesAndRanges=images,
                      request=pin(request), derivedActualV11Script=pin(OUT / 'script.sh'),
                      hostShellSyntaxCheckPassed=True, exactGuardedCacheMembers=['25', '27-data', 'main'],
                      sshTimeoutSeconds=55, sshConnectTimeoutSeconds=8, passwordFromGetpassOnly=True,
                      outputMustNotExist=str(outputs), readCommand=['python3', str(OUT / 'read-once.py')],
                      noReceiptCreated=True, inputs=fixed_inputs,
                      notEstablished=['Native sandbox flags=3 meaning', 'macOS27 profile compatibility on iPadOS16',
                                      'sandbox init or compile success', 'Guest boot'])
    dump(OUT / 'derivation.json', derivation)
    all_pins = fixed_inputs + [pin(OUT / n) for n in ('request.json', 'script.sh', 'read-once.py', 'derivation.json')]
    dump(OUT / 'freeze.json', dict(schema='Finite readonly native sandbox prepared capture freeze v1',
                                  deviceOperations=0, captureExecuted=False, files=all_pins))
    dump(OUT / 'candidate.json', dict(schema='Finite readonly native sandbox prepared capture candidate v1',
                                     deviceOperations=0, captureExecuted=False, noReceiptCreated=True,
                                     requestedBytes=total, requestedRanges=len(rows), reader=pin(READER), headers=pin(HEADERS),
                                     request=pin(request), dispatchSource=pin(OUT / 'read-once.py'),
                                     derivedActualV11Script=pin(OUT / 'script.sh'), derivation=pin(OUT / 'derivation.json'),
                                     freeze=pin(OUT / 'freeze.json'), readCommand=derivation['readCommand'],
                                     output=str(outputs), source=pin(Path(__file__))))
    print(json.dumps(dict(candidate=pin(OUT / 'candidate.json'), freeze=pin(OUT / 'freeze.json'),
                          requestedBytes=total, requestedRanges=len(rows), deviceOperations=0)))


if __name__ == '__main__':
    main()
