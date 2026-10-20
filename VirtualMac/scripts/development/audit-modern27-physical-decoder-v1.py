#!/usr/bin/env python3
"""Evaluate the genuine modern register decoder as bounded integer data."""
import ast
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import types

R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D = N / 'modern27-native-physical-decoder-readonly-v1'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pin(path):
    path = Path(path).resolve()
    require(path.is_file() and not path.is_symlink(), 'regular input')
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def raw(data, image, start, end):
    require(0 <= start <= end, 'bounded range')
    address = image['imageBase'] + start
    matches = [s for s in image['segments'] if s['address'] <= address and
               address + end - start <= s['address'] + s['fileBytes']]
    require(len(matches) == 1, 'unique immutable table segment')
    segment = matches[0]
    offset = segment['offset'] + address - segment['address']
    require(offset + end - start <= len(data), 'file table range')
    return data[offset:offset + end - start]


class ExplicitGuards(ast.NodeTransformer):
    def visit_Assert(self, node):
        return ast.copy_location(ast.If(test=ast.UnaryOp(op=ast.Not(), operand=node.test),
            body=[ast.Raise(exc=ast.Call(func=ast.Name(id='ValueError', ctx=ast.Load()),
                args=[node.msg or ast.Constant(value='integer interpreter guard')], keywords=[]), cause=None)],
            orelse=[]), node)

    def visit_Constant(self, node):
        if node.value == 0x5e2c:
            return ast.copy_location(ast.Constant(value=0x6e2c), node)
        return node


def main():
    derivation = json.loads((D / 'derivation.json').read_bytes())
    image = derivation['primaryImage']
    primary = Path(image['path'])
    require(pin(primary)['sha256'] == '4d334d43c5628d134ef6b0f8ceef9a4c3c620467b284f92dc1c49b16bfc495a3', 'actual image pin')
    require(image['uuid'] == '1b4f3a6a055836c6850d886311584afc', 'actual image UUID')
    data = primary.read_bytes()
    rows = []
    for line in (D / 'mapper.asm').read_text().splitlines():
        match = re.match(r'^([0-9a-f]+): ([0-9a-f]{8})\s+(.+)$', line)
        if match:
            rows.append(dict(rva=int(match[1], 16) - image['imageBase'],
                machineWord=match[2], instruction=match[3]))
    machine = raw(data, image, 0x6e2c, 0x7b68)
    require(len(rows) == len(machine) // 4 and
        b''.join(struct.pack('<I', int(q['machineWord'], 16)) for q in rows) == machine,
        'complete genuine decoder machine words')
    require(hashlib.sha256(machine).hexdigest() == '984af4fa9b49400ab0e3b1ca5b894e9962c73899502b8ec03d19727424f6d8da', 'whole decoder bytes')
    original = N / 'native-system-register-contract-v1/audit.py'
    tree = ast.parse(original.read_text())
    evaluator = next(q for q in tree.body if isinstance(q, ast.FunctionDef) and q.name == 'evaluator')
    require(sum(isinstance(q, ast.Constant) and q.value == 0x5e2c for q in ast.walk(evaluator)) == 1,
        'only the decoder entry is changed')
    module = ast.fix_missing_locations(ast.Module(body=[ExplicitGuards().visit(evaluator)], type_ignores=[]))
    transformed = ast.unparse(module) + '\n'
    require(not any(isinstance(q, ast.Assert) for q in ast.walk(module)), 'guards survive optimized Python')
    namespace = dict(struct=struct, re=re, integer=lambda text: int(text.lstrip('#'), 0),
        source=types.SimpleNamespace(raw=raw))
    exec(compile(module, str(original) + ':integer-only', 'exec'), namespace)
    evaluate = namespace['evaluator'](data, image, rows)
    accepted = []
    for logical in range(65536):
        result = evaluate(logical)
        if result['valid']:
            require(result['offset'] > 0 and result['offset'] + 8 <= 0x4000, 'bounded physical field')
            accepted.append(dict(identifier=logical, **result))
    require(accepted == json.loads((D / 'accepted-descriptors.json').read_bytes()), 'all existing 16bit results joined')
    require(len(accepted) == 137, 'actual accepted count')
    chosen = [q for q in accepted if q['offset'] == 0x688]
    require(chosen == [dict(identifier=0x8010, valid=True, offset=0x688, mask=2)], 'unique MDCCINT physical route')
    require(not any(q['offset'] in (0x410, 0x6a0) for q in accepted), 'unidentified fields are not guessed')
    trace = json.loads((D / 'selected-traces.json').read_bytes())[0]
    require(trace['identifier'] == 0x8010 and evaluate(0x8010, True) ==
        {k: v for k, v in trace.items() if k != 'identifier'}, 'selected original trace')
    for logical in (0x10000, 0x18010, 0x7fffffff, 0x80000000, 0xffffffff):
        require(not evaluate(logical)['valid'], 'outside public 16bit decoder domain')
    report = dict(schema='Genuine modern27 physical decoder integer audit v1',
        primaryImage=pin(primary), derivation=pin(D / 'derivation.json'), wholeMachineSHA256=hashlib.sha256(machine).hexdigest(),
        decoderRange=[0x6e2c, 0x7b68], originalEvaluator=pin(original),
        evaluatorTransformation='AST extract only evaluator; sole entry5e2c->6e2c; all asserts become explicit ValueError guards',
        transformedEvaluatorSHA256=hashlib.sha256(transformed.encode()).hexdigest(),
        optimizedPython=bool(sys.flags.optimize), exhaustive16BitCases=65536, acceptedPhysicalCount=137,
        modernMDCCINT=chosen[0], unidentifiedModernOffsets=[0x410, 0x6a0],
        nativeCalls=0, deviceOperations=0, AppleCodeExecuted=False, full27Backend=False,
        source=pin(Path(__file__)))
    destination = D / ('audit-optimized.json' if sys.flags.optimize else 'audit.json')
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(report=pin(destination), exhaustiveCases=65536, nativeCalls=0)))


if __name__ == '__main__':
    main()
