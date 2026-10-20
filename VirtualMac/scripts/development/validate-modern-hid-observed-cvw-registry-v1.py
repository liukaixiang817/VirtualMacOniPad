#!/usr/bin/env python3
"""Run exact original-program parser regression in an ordinary Mac process."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('registry_generate', HERE / 'generate-modern-hid-observed-cvw-registry-v1.py')
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
p, HOST = g.p, g.b.HOST


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    inputs = [Path(__file__), HOST / 'modern_swift_hid_observed_cvw_registry_fixture.cpp']
    inputs += [HOST / ('modern_swift_hid_observed_cvw_v2_' + suffix) for suffix in ('compat.cpp', 'compat.h')]
    pins = list(map(p.pin, inputs)); commands = []

    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=list(map(str, argv)), exit=result.returncode))
        p.save(out / 'commands.json', commands)
        assert result.returncode == 0, (label, result.stderr.decode())
        return result

    try:
        registry = g.generate(out)
        roles = []
        sdk = run('sdk', ['xcrun', '--sdk', 'macosx', '--show-sdk-path']).stdout.decode().strip()
        for role in ('mac', 'mac-sanitized'):
            exe = out / role
            compile = ['xcrun', '--sdk', 'macosx', 'clang++', '-target', 'arm64e-apple-macos13.0',
                '-isysroot', sdk, '-std=c++17', '-O2', '-I', out, '-I', HOST,
                HOST / 'modern_swift_hid_observed_cvw_registry_fixture.cpp', '-lswiftCore', '-lobjc', '-o', exe]
            if role == 'mac-sanitized': compile += ['-fsanitize=address,undefined']
            run(role + '-build', compile)
            result = run(role + '-parse', [exe]); actual = json.loads(result.stdout)
            assert not result.stderr and actual['completedOriginalMetadataSchemasValidated'] == 65
            assert actual['counterexamplesRejected'] >= 455
            roles.append(dict(role=role, executable=p.pin(exe), actualOrdinaryMac=actual))
        assert pins == list(map(p.pin, inputs))
        report = dict(schema='Actual 37 original HID CVW programs and 65 metadata parser regression v1',
            inputs=pins, registrySource=registry, roles=roles, originalGetterExecuted=False,
            productionRuntimeIdentityGatePassed=False, originalHIDLoaded=False, deviceOperations=0,
            nativeIOSExecuted=False, originalSymbolEntryProvided=False, full27Backend=False)
        p.save(out / 'review.json', report)
        files = [x for x in out.rglob('*') if x.is_file()]
        p.save(out / 'freeze.json', dict(files=pins + registry['inputs'] + list(map(p.pin, files))))
        print(json.dumps(dict(review=p.pin(out / 'review.json'), roles=roles)))
    except Exception as error:
        failed = out / 'failed-sources'; failed.mkdir(exist_ok=True)
        for path in inputs + [Path(g.__file__)]: (failed / path.name).write_bytes(path.read_bytes())
        p.save(out / 'failure.json', dict(error=repr(error), inputs=pins, deviceOperations=0))
        raise


if __name__ == '__main__': main()
