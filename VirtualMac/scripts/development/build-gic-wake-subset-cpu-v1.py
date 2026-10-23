#!/usr/bin/env python3
"""CPU93: remove redundant priority arbitration from GIC wake notification."""
import difflib
import importlib.util
import json
import shlex
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[3]
S = R / 'VirtualMac/vz/host'
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
O = N / 'cpu-gic-wake-subset-v93-attempt1'
spec = importlib.util.spec_from_file_location('cpu_build_primitives', Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
pin = base.pin


def main():
    O.mkdir(mode=0o700)
    commands = []

    def run(label, args):
        args = list(map(str, args))
        result = subprocess.run(args, capture_output=True, timeout=90)
        (O / (label + '.stdout')).write_bytes(result.stdout)
        (O / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=args, exit=result.returncode))
        base.save(O / 'commands.json', commands)
        assert result.returncode == 0, result.stderr.decode()

    for name in ['test-modern-gic-wake-subset-v18.c',
                 'test-modern-gic-icc-local-generations-v16.c',
                 'test-modern-gic-timer-generations-v16.c']:
        source = S / name
        if name.endswith('v16.c'):
            text = source.read_text()
            assert text.count('modern_gic_v3_engine_v16_local_icc_generations.c') == 1
            source = O / name
            source.write_text(text.replace('modern_gic_v3_engine_v16_local_icc_generations.c',
                                           'modern_gic_v3_engine_v18_wake_subset.c'))
        exe = O / (Path(name).stem + '-test')
        run('compile-' + name, ['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra',
                              '-Werror', '-pthread', '-I', S, source, '-o', exe])
        run('run-' + name, [exe])

    oldpath = N / 'cpu-gic-single-pass-v92-attempt1/candidate.json'
    old = json.loads(oldpath.read_bytes())
    objects = old['changedCPUObjects'] + old['inheritedCPUObjects']
    assert len(objects) == 29 and len(old['changedCPUObjects']) == 1
    for row in objects:
        assert pin(row['path']) == row
    oldobj = old['changedCPUObjects'][0]['path']
    recipe = json.loads((oldpath.parent / 'commands.json').read_bytes())
    args = next(row['argv'][:] for row in recipe if row['label'] == 'compile-gic17')
    obj = O / 'modern_gic_v3_engine_v18_wake_subset.o'
    dep = O / 'GIC18.d'
    args[args.index('-c') + 1] = str(S / 'modern_gic_v3_engine_v18_wake_subset.c')
    args[args.index('-o') + 1] = str(obj)
    args[args.index('-MF') + 1] = str(dep)
    run('compile-gic18', args)
    args = next(row['argv'][:] for row in recipe if row['label'] == 'link-cpu')
    assert args.count(oldobj) == 1
    args[args.index(oldobj)] = str(obj)
    cpu = O / 'VM27HVVMProduction.dylib'
    args[args.index('-o') + 1] = str(cpu)
    run('link-cpu', args)
    run('validate-cpu', ['xcrun', 'dyld_info', '-validate_only', cpu])

    before = base.image_profile(Path(old['cpu']['path']).read_bytes(), 'cpu')
    after = base.image_profile(cpu.read_bytes(), 'cpu')
    assert set(after.exports) == set(before.exports)
    assert all(after.exports[key]['flags'] == before.exports[key]['flags'] for key in after.exports)
    semantics = lambda rows: [{k: v for k, v in row.items() if k not in ('at', 'index')} for row in rows]
    assert semantics(after.loads) == semantics(before.loads)
    assert sorted((row['name'], row['weak']) for row in after.imports) == sorted(
        (row['name'], row['weak']) for row in before.imports)
    sources = []
    for name in shlex.split(dep.read_text().replace('\\\n', ' ').split(':', 1)[1]):
        path = Path(name).resolve()
        if path.is_relative_to(R):
            sources.append(pin(path))
    (O / 'readable-source.diff').write_text(''.join(difflib.unified_diff(
        (S / 'modern_gic_v3_engine_v17_single_pass.c').read_text().splitlines(True),
        (S / 'modern_gic_v3_engine_v18_wake_subset.c').read_text().splitlines(True),
        fromfile='GIC17', tofile='GIC18')))
    result = dict(schema='CPU93 one GIC18 wake-notification object; injection arbitration whole',
        baseline=pin(oldpath), cpu=pin(cpu), changedCPUObjects=[pin(obj)],
        inheritedCPUObjects=[row for row in objects if row['path'] != oldobj], sources=sources,
        comparisons=[dict(provider='VM27HVVMProduction.dylib', actualExports=after.exports,
            actualImports=after.imports, actualLoads=after.loads, addedImports=[])],
        actualExportsAndImportsUnchanged=True, localDifferentialQueries=168000,
        concurrentOwnerAndTimerTestsPassed=True, deviceOperations=0)
    assert len(result['inheritedCPUObjects']) == 28
    base.save(O / 'candidate.json', result)
    base.save(O / 'freeze.json', dict(files=[pin(path) for path in O.rglob('*') if path.is_file()]
        + [pin(__file__), pin(oldpath), pin(S / 'test-modern-gic-wake-subset-v18.c'), *sources],
        deviceOperations=0))
    print(json.dumps(pin(O / 'candidate.json')))


if __name__ == '__main__':
    main()
