#!/usr/bin/env python3
"""Adjudicate only saved RAW v2 execution. No device access and no native API execution."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
ACTUAL = N / 'diskimages2-foundation-owned-raw-native-v2'
BUILD = N / 'diskimages2-foundation-owned-raw-build-v2'
WIRE = N / 'diskimages2-foundation-owned-raw-v2-wire-independent-review-v1'
PARSER = ROOT / 'VirtualMac/scripts/tests/validate-modern-diskimages2-foundation-owned-return-raw-v2-wire-native.py'
SHA = lambda data: hashlib.sha256(data).hexdigest()


def main():
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument('--output', type=Path, required=True)
    output = arguments.parse_args().output.resolve()
    output.mkdir()
    source = BUILD / 'source/modern_diskimages2_owned_raw_owned_return_probe.m'
    assert SHA(source.read_bytes()) == '5c610629ec6109fd5975f4a6b46146ff91b9749f5057bf589dab9eddc2ef240f'
    assert SHA(PARSER.read_bytes()) == '231e799d24988f58fe90ae3a075a66217cc6c8a86b52dc40efbd179807ae1529'
    assert SHA((ACTUAL / 'result.json').read_bytes()) == '17a14e06d87a458086b0783dec2672ce748713e602089c8cec9d04b38363bb04'
    assert SHA((ACTUAL / 'native.stdout').read_bytes()) == 'c85f122323bdece0fbd5644c7917644dd8cfe495f3b9fbb27286641fb65cf1df'
    assert SHA((ACTUAL / 'plan.json').read_bytes()) == '895a26a109503cf2b8d4686f53458fc1633e312210c9117decf4435bf074269e'
    old = json.loads((ACTUAL / 'result.json').read_bytes())
    assert old['passed'] is False and old['validationError'] == 'AssertionError'
    assert old['childPID'] == 46014 and old['observedWaitExit'] == 0 and old['childAbsent'] is True
    assert old['originalVMMExecuted'] is False and old['completeMacOS27Backend'] is False
    assert (ACTUAL / 'native.exit').read_bytes() == b'0\n'
    assert (ACTUAL / 'native.stderr').read_bytes() == b'NATIVE_STARTED pid=46014\nNATIVE_WAIT pid=46014 exit=0\n'
    assert b'NATIVE_STARTED pid=46014\nNATIVE_WAIT pid=46014 exit=0\n' in (ACTUAL / 'runner.stdout').read_bytes()

    unchanged = {}
    for folder, expected in [
            ('diskimages2-foundation-owned-raw-v2-wire-independent-review-v1', 71),
            ('diskimages2-foundation-owned-raw-independent-review-v2', 34),
            ('diskimages2-foundation-owned-return-parser-review-v2', 6),
            ('di2-open-owned-return-static-audit-v1', 15)]:
        items = json.loads((N / folder / 'freeze.json').read_bytes())['files']
        assert len(items) == expected
        for item in items:
            path = Path(item['path'])
            if not path.is_absolute(): path = ROOT / path
            content = path.read_bytes()
            assert SHA(content) == item['sha256'] and len(content) == item['bytes']
        unchanged[folder] = len(items)

    processes = []
    def run(label, argv):
        child = subprocess.Popen([str(value) for value in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try: stdout, stderr = child.communicate(timeout=40)
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate(); raise
        (output / (label + '.stdout')).write_bytes(stdout)
        (output / (label + '.stderr')).write_bytes(stderr)
        processes.append(dict(label=label, argv=[str(value) for value in argv], PID=child.pid, wait=child.returncode, reaped=True))
        assert child.returncode == 0, stderr.decode(errors='replace')[-4000:]
        return stdout

    # Compile the immutable writer as Objective-C C11 with the original target,
    # SDK and flags. This performs syntax/AST analysis only, never native execution.
    sdk = run('sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).decode().strip()
    ast = run('original-error-ast', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk,
        '-std=c11', '-O2', '-fno-objc-arc', '-fobjc-exceptions', '-fptrauth-abi-version=0',
        '-fno-typed-memory-operations-experimental', '-Wno-deprecated-declarations', '-I', BUILD / 'ios',
        '-Xclang', '-ast-dump', '-Xclang', '-ast-dump-filter=OriginalError', '-fsyntax-only', source]).decode()
    assert 'OriginalError' in ast
    assert re.search(r"ObjCBoxedExpr[^\n]+selector=numberWithInt:", ast)
    assert re.search(r"BinaryOperator[^\n]+'int' '!='", ast)
    assert '@"hasNSError": @(error != nil)' in source.read_text()

    module_spec = importlib.util.spec_from_file_location('raw_wire_saved', PARSER)
    module = importlib.util.module_from_spec(module_spec); module_spec.loader.exec_module(module)
    actual = module.native_transcript(ACTUAL / 'native.stdout', 46014, 0)
    assert actual['originalDI2ObjectAndDescriptorCalls'] == 12
    rows = [json.loads(line) for line in (ACTUAL / 'native.stdout').read_bytes().splitlines()]
    assert len(rows) == 103 and type(rows[90]['hasNSError']) is int and rows[90]['hasNSError'] == 1
    assert rows[90]['domain'] == 'NSPOSIXErrorDomain' and rows[90]['code'] == 2

    post = (ACTUAL / 'post-raw-v2-reparse.sh').read_text()
    assert (ACTUAL / 'post-raw-v2-reparse.stdout').read_bytes() == b'RAW_V2_EXACT_PID_AND_ALL_OWN_FILES_ABSENT\n'
    assert (ACTUAL / 'post-raw-v2-reparse.stderr').read_bytes() == b''
    assert post.startswith('set -eu\n') and 'if kill -0 46014 2>/dev/null; then exit 7; fi\n' in post
    plan = json.loads((ACTUAL / 'plan.json').read_bytes())
    directory = plan['deviceDirectory']
    assert 'for file in ' + directory + '/owned-raw-??????; do [ ! -e "$file" ] && [ ! -L "$file" ]; done\n' in post
    assert '[ "$state" = OFF ]' in post
    assert len(plan['files']) == 14
    for item in plan['files']:
        remote = directory + '/' + item['name']
        assert f'[ -f {remote} ] && [ ! -L {remote} ]' in post
        assert f'[ "$(sha256sum {remote} | cut -d " " -f1)" = {item["sha256"]} ]' in post
        assert f'[ "$(ldid -h {remote} 2>&1 | sed -n "s/^CDHash=//p")" = {item["cdhash"]} ]' in post
        assert f'[ "$(stat -c %u {remote})" = 0 ]' in post

    rejected = []
    models = [
        ('NSErrorBool', 90, 'hasNSError', True), ('NSErrorFloat', 90, 'hasNSError', 1.0),
        ('NSErrorZero', 90, 'hasNSError', 0), ('NSErrorEmptyDomain', 90, 'domain', ''),
        ('UnclosedFD', 87, 'closedByFramework', False), ('ChangedReopenInode', 88, 'inode', rows[88]['inode'] + 1),
        ('NumericSummaryBool', 102, 'passed', 1), ('TwoWrites', 102, 'originalFDWrites', 2),
        ('BorrowedFDCloseByProbe', 87, 'borrowedFDCloseCallsByProbe', 1), ('DesktopSecurityCall', 91, 'calls', 1),
        ('GuestDiskPath', 85, 'path', '/var/mobile/guest.dmg')]
    for name, index, key, value in models:
        mutated = copy.deepcopy(rows); mutated[index][key] = value
        with tempfile.TemporaryDirectory(prefix='di2-saved-control-') as scratch:
            path = Path(scratch) / 'receipt.jsonl'
            path.write_text(''.join(json.dumps(row) + '\n' for row in mutated))
            try: module.native_transcript(path, 46014, 0)
            except AssertionError: rejected.append(name)
            else: raise AssertionError('negative control accepted: ' + name)
    try: module.native_transcript(ACTUAL / 'native.stdout', 46014, 81)
    except AssertionError: rejected.append('NonzeroActualWait')
    else: raise AssertionError('nonzero actual wait accepted')
    assert len(rejected) == 12

    def pin(path):
        path = Path(path); content = path.read_bytes()
        return dict(path=str(path), bytes=len(content), sha256=SHA(content))
    result = dict(scope='savedexecutionOnly-ownedRAW-v2-wire-adjudication', passed=True,
        oldFailedWrapperPreserved=True, oldWrapperPassed=False, oldWrapperError='AssertionError',
        actualNativeProgramSummaryPassed=True, actualPID=46014, actualWait=0,
        exactSourceNSErrorCType='int', exactSourceNSErrorNSNumberConstructor='numberWithInt:',
        exactSavedNSErrorJSONType='integer', exactSavedNSErrorValue=1, JSONCoercionOrNormalization=False,
        transcriptRows=103, originalDI2Calls=12, originalOpenCalls=3, originalHandles=2, checks=41,
        frameworkClosedBothBorrowedFDs=True, persistenceAndReopenVerified=True,
        directPOSIXReads=3, directPOSIXWrites=1, readBytes=12288, writeBytes=4096, persistenceCall='fsync',
        ownedRAWBytes=131072, ownedFileMode=384, desktopSecurityCalls=0,
        exactPIDExternallyAbsent=True, allOwnRAWFilesExternallyAbsent=True, staged14SourcePinsExternallyPreserved=True,
        savedExecutionOnly=True, deviceOperations=False, newNativeExecutions=0,
        oldPinSetsUnchanged=unchanged, negativeControlsRejected=rejected,
        originalDI2DataReadWriteMethodsExercised=False, AppleUIORingsABIProven=False,
        ASIFProven=False, VMMBlockDeviceIntegrationProven=False, originalVMMExecuted=False,
        guestInstructionOracle=0, full27Backend=False, native=actual,
        inputs=[pin(path) for path in [source, PARSER, ACTUAL / 'plan.json', ACTUAL / 'native.stdout',
            ACTUAL / 'native.stderr', ACTUAL / 'native.exit', ACTUAL / 'runner.stdout', ACTUAL / 'result.json',
            ACTUAL / 'post-raw-v2-reparse.sh', ACTUAL / 'post-raw-v2-reparse.stdout', ACTUAL / 'post-raw-v2-reparse.stderr']])
    (output / 'processes.json').write_text(json.dumps(processes, indent=2) + '\n')
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    files = set(path for path in output.iterdir() if path.is_file())
    files.update(Path(item['path']) for item in result['inputs'])
    files.update([Path(__file__), WIRE / 'verification.json', WIRE / 'freeze.json'])
    (output / 'freeze.json').write_text(json.dumps(dict(files=[pin(path) for path in sorted(files)]), indent=2) + '\n')
    print(json.dumps(dict(result=str(output / 'result.json'), resultSHA256=SHA((output / 'result.json').read_bytes()),
        freezeSHA256=SHA((output / 'freeze.json').read_bytes()), frozenFiles=len(files), passed=True), indent=2))


if __name__ == '__main__': main()
